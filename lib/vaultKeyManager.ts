// =============================================================================
// lib/vaultKeyManager.ts — Session-Scoped Vault Key Manager
//
// Manages the in-memory lifecycle of the unwrapped Vault Key.
// The raw Vault Key never leaves the browser's memory and is never persisted.
// =============================================================================

"use client";

import { getSupabaseBrowserClient } from "@/lib/supabase/browser-client";
import {
    generateUserSalt,
    deriveMasterKey,
    generateVaultKey,
    wrapVaultKey,
    unwrapVaultKey,
} from "@/lib/crypto";
import { saveInitialEncryptionKeys } from "@/app/actions/encryption-keys";

// In-memory store — restored from sessionStorage on page refresh, cleared on tab close
let vaultKey: CryptoKey | null = null;

const SESSION_KEY = "nokslock_vk";

async function saveKeyToSession(key: CryptoKey): Promise<void> {
    try {
        const raw = await crypto.subtle.exportKey("raw", key);
        const bytes = new Uint8Array(raw);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        sessionStorage.setItem(SESSION_KEY, btoa(binary));
    } catch {
        // Non-critical — silently ignore
    }
}

/**
 * Try to restore the vault key from sessionStorage (survives page refresh,
 * cleared when the tab or browser is closed).
 * Returns true if the key was successfully restored.
 */
export async function tryRestoreVaultKey(): Promise<boolean> {
    if (vaultKey) return true;
    try {
        const stored = sessionStorage.getItem(SESSION_KEY);
        if (!stored) return false;
        const binaryString = atob(stored);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
        vaultKey = await crypto.subtle.importKey(
            "raw",
            bytes.buffer,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"],
        );
        return true;
    } catch {
        sessionStorage.removeItem(SESSION_KEY);
        return false;
    }
}

// =============================================================================
// REGISTRATION: Initialize keys for a brand-new user
// =============================================================================

/**
 * Called during registration after `supabase.auth.signUp()` succeeds.
 *
 * 1. Generate a unique salt
 * 2. Derive the Master Key from (password + salt)
 * 3. Generate a random Vault Key
 * 4. Wrap the Vault Key with the Master Key
 * 5. Persist { user_salt, encrypted_vault_key } to Supabase
 * 6. Store the raw Vault Key in memory
 */
export async function initializeVaultKey(
    password: string,
    userId: string,
): Promise<void> {
    const saltBase64 = generateUserSalt();
    const masterKey = await deriveMasterKey(password, saltBase64);
    const newVaultKey = await generateVaultKey();
    const encryptedVaultKey = await wrapVaultKey(newVaultKey, masterKey);

    // Use server action with admin client — the user has no active session
    // yet (email not confirmed), so browser client would fail RLS.
    await saveInitialEncryptionKeys(userId, saltBase64, encryptedVaultKey);

    vaultKey = newVaultKey;
    await saveKeyToSession(vaultKey);
}

// =============================================================================
// LOGIN: Unlock the vault for a returning user
// =============================================================================

/**
 * Called during login after `supabase.auth.signInWithPassword()` succeeds.
 *
 * 1. Fetch { user_salt, encrypted_vault_key } from Supabase
 * 2. Derive the Master Key from (password + salt)
 * 3. Unwrap the Vault Key
 * 4. Store the raw Vault Key in memory
 */
export async function unlockVault(
    password: string,
    userId: string,
): Promise<void> {
    const supabase = getSupabaseBrowserClient();

    // Step 1: Fetch key material
    const { data, error } = await (
        supabase.from("user_encryption_keys") as any
    )
        .select("user_salt, encrypted_vault_key")
        .eq("user_id", userId)
        .single();

    if (error || !data) {
        throw new Error(
            "Encryption keys not found. This account may not have vault encryption set up.",
        );
    }

    // Step 2: Derive Master Key
    const masterKey = await deriveMasterKey(password, data.user_salt);

    // Step 3: Unwrap Vault Key
    try {
        vaultKey = await unwrapVaultKey(data.encrypted_vault_key, masterKey);
        await saveKeyToSession(vaultKey);
    } catch {
        throw new Error(
            "Failed to unlock vault. The password may be incorrect or the key data is corrupted.",
        );
    }
}

// =============================================================================
// ACCESSORS
// =============================================================================

/**
 * Get the in-memory Vault Key. Throws if the vault has not been unlocked.
 *
 * Components call this before encrypting/decrypting data.
 */
export function getVaultKey(): CryptoKey {
    if (!vaultKey) {
        throw new Error(
            "Vault is locked. Please log in again to unlock your vault.",
        );
    }
    return vaultKey;
}

/**
 * Check if the Vault Key is currently in memory (non-throwing).
 * Used by the dashboard to decide whether to show the vault-locked overlay.
 */
export function isVaultUnlocked(): boolean {
    return vaultKey !== null;
}

/**
 * Clear the in-memory Vault Key. Called on logout or session timeout.
 */
export function clearVaultKey(): void {
    vaultKey = null;
    sessionStorage.removeItem(SESSION_KEY);
}

// =============================================================================
// PASSWORD CHANGE: Re-wrap vault key with a new password
// =============================================================================

/**
 * Re-wrap the existing in-memory Vault Key with a new password.
 * Called during password change (settings) when the user is logged in
 * and the vault is already unlocked.
 *
 * Returns the old salt and encrypted vault key for rollback if the
 * subsequent password update fails.
 */
export async function rewrapVaultKey(
    newPassword: string,
    userId: string,
): Promise<{ oldSalt: string; oldEncryptedVaultKey: string }> {
    const supabase = getSupabaseBrowserClient();
    const currentVaultKey = getVaultKey(); // throws if vault is locked

    // Fetch current key material (for rollback)
    const { data: oldRow, error: fetchError } = await (
        supabase.from("user_encryption_keys") as any
    )
        .select("user_salt, encrypted_vault_key")
        .eq("user_id", userId)
        .single();

    if (fetchError || !oldRow) {
        throw new Error("Failed to fetch current encryption keys for re-wrapping.");
    }

    // Generate new salt and derive new master key
    const newSalt = generateUserSalt();
    const newMasterKey = await deriveMasterKey(newPassword, newSalt);

    // Wrap the existing vault key with the new master key
    const newEncryptedVaultKey = await wrapVaultKey(currentVaultKey, newMasterKey);

    // Persist new wrapped key + salt to DB
    const { error: updateError } = await (
        supabase.from("user_encryption_keys") as any
    )
        .update({
            user_salt: newSalt,
            encrypted_vault_key: newEncryptedVaultKey,
        })
        .eq("user_id", userId);

    if (updateError) {
        throw new Error(`Failed to update encryption keys: ${updateError.message}`);
    }

    return {
        oldSalt: oldRow.user_salt,
        oldEncryptedVaultKey: oldRow.encrypted_vault_key,
    };
}

/**
 * Restore the old vault key wrapping after a failed password update.
 * This is the rollback path for `rewrapVaultKey`.
 */
export async function restoreVaultKeyWrapping(
    userId: string,
    oldSalt: string,
    oldEncryptedVaultKey: string,
): Promise<void> {
    const supabase = getSupabaseBrowserClient();
    await (supabase.from("user_encryption_keys") as any)
        .update({
            user_salt: oldSalt,
            encrypted_vault_key: oldEncryptedVaultKey,
        })
        .eq("user_id", userId);
}

// =============================================================================
// FORGOT PASSWORD: Reset vault with a new key (old data becomes inaccessible)
// =============================================================================

/**
 * Generate a completely new vault key and wrap it with the new password.
 * Called during forgot-password flow when the old password is unknown
 * and the vault key cannot be recovered.
 *
 * WARNING: All previously encrypted vault data becomes permanently inaccessible.
 */
export async function resetVaultKey(
    newPassword: string,
    userId: string,
): Promise<void> {
    const supabase = getSupabaseBrowserClient();

    const newSalt = generateUserSalt();
    const newMasterKey = await deriveMasterKey(newPassword, newSalt);
    const newVaultKey = await generateVaultKey();
    const newEncryptedVaultKey = await wrapVaultKey(newVaultKey, newMasterKey);

    const { error } = await (
        supabase.from("user_encryption_keys") as any
    )
        .update({
            user_salt: newSalt,
            encrypted_vault_key: newEncryptedVaultKey,
        })
        .eq("user_id", userId);

    if (error) {
        throw new Error(`Failed to reset vault keys: ${error.message}`);
    }

    vaultKey = newVaultKey;
    await saveKeyToSession(newVaultKey);
}

// =============================================================================
// EXPORT
// =============================================================================

/**
 * Export the in-memory Vault Key as raw base64-encoded bytes.
 *
 * Used exclusively during Dead Man's Switch setup so the vault key can be
 * wrapped with the Emergency Key (PBKDF2 + AES-GCM) before escrow.
 * The exported bytes are never persisted directly — only the wrapped form is.
 *
 * Throws if the vault is locked (i.e. the user must be authenticated).
 */
export async function exportVaultKeyMaterial(): Promise<string> {
    const key = getVaultKey(); // throws "Vault is locked" if not in memory
    const rawBytes = await crypto.subtle.exportKey("raw", key);
    const bytes = new Uint8Array(rawBytes);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
