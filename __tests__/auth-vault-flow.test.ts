/**
 * Tests for Authentication & Vault Key Flows
 *
 * Verifies the critical integration between auth operations (register, login,
 * password change, forgot password) and vault encryption key management.
 *
 * These tests caught the bug where changing a password broke vault unlock
 * because the vault key was not re-wrapped with the new password.
 */

import {
  generateUserSalt,
  deriveMasterKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  encryptData,
  decryptData,
} from "@/lib/crypto";

// =============================================================================
// Mock Supabase browser client
// =============================================================================

const mockSelect = jest.fn();
const mockEq = jest.fn();
const mockSingle = jest.fn();
const mockInsert = jest.fn();
const mockUpdate = jest.fn();

function createChainableMock(terminal?: { data?: any; error?: any }) {
  const chain: any = {};
  chain.select = jest.fn().mockReturnValue(chain);
  chain.eq = jest.fn().mockReturnValue(chain);
  chain.single = jest.fn().mockResolvedValue(terminal ?? { data: null, error: null });
  chain.insert = jest.fn().mockResolvedValue(terminal ?? { data: null, error: null });
  chain.update = jest.fn().mockReturnValue(chain);
  return chain;
}

let encryptionKeysChain: any;

jest.mock("@/lib/supabase/browser-client", () => ({
  getSupabaseBrowserClient: jest.fn(() => ({
    from: jest.fn((table: string) => {
      if (table === "user_encryption_keys") return encryptionKeysChain;
      return createChainableMock();
    }),
    auth: {
      signInWithPassword: jest.fn(),
      signUp: jest.fn(),
      updateUser: jest.fn(),
      verifyOtp: jest.fn(),
      getUser: jest.fn(),
    },
  })),
}));

// Mock sessionStorage
const sessionStorageMap = new Map<string, string>();
Object.defineProperty(globalThis, "sessionStorage", {
  value: {
    getItem: (key: string) => sessionStorageMap.get(key) ?? null,
    setItem: (key: string, value: string) => sessionStorageMap.set(key, value),
    removeItem: (key: string) => sessionStorageMap.delete(key),
    clear: () => sessionStorageMap.clear(),
  },
  writable: true,
});

// Import AFTER mocks are set up
import {
  initializeVaultKey,
  unlockVault,
  rewrapVaultKey,
  restoreVaultKeyWrapping,
  resetVaultKey,
  getVaultKey,
  isVaultUnlocked,
  clearVaultKey,
} from "@/lib/vaultKeyManager";

// =============================================================================
// Helpers
// =============================================================================

const TEST_PASSWORD = "MyStr0ng!Pass123";
const TEST_USER_ID = "user-test-uuid-1234";

/** Simulate what the DB stores after initializeVaultKey */
async function createStoredKeyMaterial(password: string) {
  const salt = generateUserSalt();
  const masterKey = await deriveMasterKey(password, salt);
  const vaultKey = await generateVaultKey();
  const encryptedVaultKey = await wrapVaultKey(vaultKey, masterKey);
  return { salt, encryptedVaultKey, vaultKey };
}

/** Export raw bytes of a CryptoKey for comparison */
async function exportKeyRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

// =============================================================================
// 1. REGISTRATION FLOW — initializeVaultKey
// =============================================================================

describe("Registration: initializeVaultKey", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sessionStorageMap.clear();
    clearVaultKey();
    encryptionKeysChain = createChainableMock();
  });

  it("creates vault key and stores it in memory after registration", async () => {
    await initializeVaultKey(TEST_PASSWORD, TEST_USER_ID);

    expect(isVaultUnlocked()).toBe(true);
    const key = getVaultKey();
    expect(key).toBeDefined();
    expect(key.type).toBe("secret");
  });

  it("persists salt and wrapped key to database", async () => {
    await initializeVaultKey(TEST_PASSWORD, TEST_USER_ID);

    expect(encryptionKeysChain.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        user_id: TEST_USER_ID,
        user_salt: expect.any(String),
        encrypted_vault_key: expect.any(String),
      })
    );

    // Verify the stored encrypted_vault_key is valid JSON with expected fields
    const insertArg = encryptionKeysChain.insert.mock.calls[0][0];
    const parsed = JSON.parse(insertArg.encrypted_vault_key);
    expect(parsed).toHaveProperty("iv");
    expect(parsed).toHaveProperty("wrappedKey");
  });

  it("stores vault key in sessionStorage for page refresh", async () => {
    await initializeVaultKey(TEST_PASSWORD, TEST_USER_ID);

    const stored = sessionStorageMap.get("nokslock_vk");
    expect(stored).toBeTruthy();
    expect(typeof stored).toBe("string");
  });

  it("throws when database insert fails", async () => {
    encryptionKeysChain.insert.mockResolvedValue({
      error: { message: "Duplicate key" },
    });

    await expect(
      initializeVaultKey(TEST_PASSWORD, TEST_USER_ID)
    ).rejects.toThrow("Failed to save encryption keys");
  });

  it("vault key can encrypt and decrypt data after registration", async () => {
    await initializeVaultKey(TEST_PASSWORD, TEST_USER_ID);

    const vaultKey = getVaultKey();
    const secret = { username: "admin", password: "s3cret!" };
    const encrypted = await encryptData(secret, vaultKey);
    const decrypted = await decryptData(encrypted, vaultKey);

    expect(decrypted).toEqual(secret);
  });
});

// =============================================================================
// 2. LOGIN FLOW — unlockVault
// =============================================================================

describe("Login: unlockVault", () => {
  let storedSalt: string;
  let storedEncryptedVaultKey: string;
  let originalVaultKey: CryptoKey;

  beforeEach(async () => {
    jest.clearAllMocks();
    sessionStorageMap.clear();
    clearVaultKey();

    // Create key material as if registration already happened
    const material = await createStoredKeyMaterial(TEST_PASSWORD);
    storedSalt = material.salt;
    storedEncryptedVaultKey = material.encryptedVaultKey;
    originalVaultKey = material.vaultKey;

    // Set up the mock to return stored key material
    encryptionKeysChain = createChainableMock({
      data: {
        user_salt: storedSalt,
        encrypted_vault_key: storedEncryptedVaultKey,
      },
      error: null,
    });
  });

  it("unlocks vault with correct password", async () => {
    await unlockVault(TEST_PASSWORD, TEST_USER_ID);

    expect(isVaultUnlocked()).toBe(true);
    const key = getVaultKey();
    expect(key).toBeDefined();
  });

  it("restored vault key matches original vault key", async () => {
    await unlockVault(TEST_PASSWORD, TEST_USER_ID);

    const restoredKey = getVaultKey();
    const originalRaw = await exportKeyRaw(originalVaultKey);
    const restoredRaw = await exportKeyRaw(restoredKey);

    expect(restoredRaw).toEqual(originalRaw);
  });

  it("fails to unlock with wrong password", async () => {
    await expect(
      unlockVault("wrong-password-123", TEST_USER_ID)
    ).rejects.toThrow("Failed to unlock vault");

    expect(isVaultUnlocked()).toBe(false);
  });

  it("fails when encryption keys not found in database", async () => {
    encryptionKeysChain = createChainableMock({
      data: null,
      error: { message: "Not found" },
    });

    await expect(
      unlockVault(TEST_PASSWORD, TEST_USER_ID)
    ).rejects.toThrow("Encryption keys not found");
  });

  it("data encrypted before logout can be decrypted after login", async () => {
    // Encrypt data with original vault key (simulating pre-logout)
    const secret = { card: "4111-1111-1111-1111", cvv: "123" };
    const encrypted = await encryptData(secret, originalVaultKey);

    // Simulate login — unlock vault
    await unlockVault(TEST_PASSWORD, TEST_USER_ID);

    // Decrypt with the restored key
    const restoredKey = getVaultKey();
    const decrypted = await decryptData(encrypted, restoredKey);

    expect(decrypted).toEqual(secret);
  });

  it("stores vault key in sessionStorage after unlock", async () => {
    await unlockVault(TEST_PASSWORD, TEST_USER_ID);

    const stored = sessionStorageMap.get("nokslock_vk");
    expect(stored).toBeTruthy();
  });
});

// =============================================================================
// 3. PASSWORD CHANGE (Settings) — rewrapVaultKey
// =============================================================================

describe("Password Change (Settings): rewrapVaultKey", () => {
  const NEW_PASSWORD = "NewStr0ng!Pass456";
  let storedSalt: string;
  let storedEncryptedVaultKey: string;
  let originalVaultKey: CryptoKey;

  beforeEach(async () => {
    jest.clearAllMocks();
    sessionStorageMap.clear();
    clearVaultKey();

    // Simulate: user registered, vault is unlocked
    const material = await createStoredKeyMaterial(TEST_PASSWORD);
    storedSalt = material.salt;
    storedEncryptedVaultKey = material.encryptedVaultKey;
    originalVaultKey = material.vaultKey;

    // Mock DB to return current key material
    encryptionKeysChain = createChainableMock();
    encryptionKeysChain.select.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.eq.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.single.mockResolvedValue({
      data: {
        user_salt: storedSalt,
        encrypted_vault_key: storedEncryptedVaultKey,
      },
      error: null,
    });
    encryptionKeysChain.update.mockReturnValue(encryptionKeysChain);
    // After update().eq() resolves
    encryptionKeysChain.eq.mockReturnValueOnce(encryptionKeysChain);
    encryptionKeysChain.eq.mockResolvedValueOnce({ error: null });

    // Unlock the vault first (user is logged in)
    // We need a fresh chain for unlockVault
    const unlockChain = createChainableMock({
      data: {
        user_salt: storedSalt,
        encrypted_vault_key: storedEncryptedVaultKey,
      },
      error: null,
    });

    // Temporarily swap chain for unlockVault
    const origChain = encryptionKeysChain;
    encryptionKeysChain = unlockChain;
    await unlockVault(TEST_PASSWORD, TEST_USER_ID);
    encryptionKeysChain = origChain;

    // Re-setup chain mocks after unlock consumed them
    encryptionKeysChain.select.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.eq.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.single.mockResolvedValue({
      data: {
        user_salt: storedSalt,
        encrypted_vault_key: storedEncryptedVaultKey,
      },
      error: null,
    });
    encryptionKeysChain.update.mockReturnValue(encryptionKeysChain);
  });

  it("re-wraps vault key with new password and updates database", async () => {
    const result = await rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID);

    // Should return old values for rollback
    expect(result.oldSalt).toBe(storedSalt);
    expect(result.oldEncryptedVaultKey).toBe(storedEncryptedVaultKey);

    // Should have called update on the DB
    expect(encryptionKeysChain.update).toHaveBeenCalledWith(
      expect.objectContaining({
        user_salt: expect.any(String),
        encrypted_vault_key: expect.any(String),
      })
    );

    // New salt should differ from old
    const updateArg = encryptionKeysChain.update.mock.calls[0][0];
    expect(updateArg.user_salt).not.toBe(storedSalt);
  });

  it("vault key in memory is unchanged after rewrap", async () => {
    const keyBefore = await exportKeyRaw(getVaultKey());

    await rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID);

    const keyAfter = await exportKeyRaw(getVaultKey());
    expect(keyAfter).toEqual(keyBefore);
  });

  it("new password can unwrap the re-wrapped vault key", async () => {
    await rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID);

    // Get the new salt and encrypted vault key that was written to DB
    const updateArg = encryptionKeysChain.update.mock.calls[0][0];
    const newSalt = updateArg.user_salt;
    const newEncryptedVaultKey = updateArg.encrypted_vault_key;

    // Derive master key with new password + new salt
    const newMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);

    // Should successfully unwrap
    const unwrapped = await unwrapVaultKey(newEncryptedVaultKey, newMasterKey);
    expect(unwrapped).toBeDefined();

    // And it should be the same vault key
    const originalRaw = await exportKeyRaw(originalVaultKey);
    const unwrappedRaw = await exportKeyRaw(unwrapped);
    expect(unwrappedRaw).toEqual(originalRaw);
  });

  it("old password cannot unwrap the re-wrapped vault key", async () => {
    await rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID);

    const updateArg = encryptionKeysChain.update.mock.calls[0][0];
    const newSalt = updateArg.user_salt;
    const newEncryptedVaultKey = updateArg.encrypted_vault_key;

    // Try to unwrap with old password — should fail
    const oldMasterKey = await deriveMasterKey(TEST_PASSWORD, newSalt);

    await expect(
      unwrapVaultKey(newEncryptedVaultKey, oldMasterKey)
    ).rejects.toThrow();
  });

  it("throws when vault is locked (not logged in)", async () => {
    clearVaultKey();

    await expect(
      rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID)
    ).rejects.toThrow("Vault is locked");
  });

  it("throws when database fetch fails", async () => {
    encryptionKeysChain.single.mockResolvedValue({
      data: null,
      error: { message: "DB error" },
    });

    await expect(
      rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID)
    ).rejects.toThrow("Failed to fetch current encryption keys");
  });

  it("encrypted data remains accessible after password change", async () => {
    // Encrypt data with current vault key
    const secret = { site: "github.com", token: "ghp_abc123" };
    const encrypted = await encryptData(secret, getVaultKey());

    // Change password (re-wrap)
    await rewrapVaultKey(NEW_PASSWORD, TEST_USER_ID);

    // Vault key is still the same in memory — data should still decrypt
    const decrypted = await decryptData(encrypted, getVaultKey());
    expect(decrypted).toEqual(secret);
  });
});

// =============================================================================
// 4. PASSWORD CHANGE ROLLBACK — restoreVaultKeyWrapping
// =============================================================================

describe("Password Change Rollback: restoreVaultKeyWrapping", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    encryptionKeysChain = createChainableMock();
    encryptionKeysChain.update.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.eq.mockResolvedValue({ error: null });
  });

  it("restores old salt and encrypted vault key in database", async () => {
    const oldSalt = "old-salt-base64==";
    const oldEncryptedVaultKey = '{"iv":"abc","wrappedKey":"def"}';

    await restoreVaultKeyWrapping(TEST_USER_ID, oldSalt, oldEncryptedVaultKey);

    expect(encryptionKeysChain.update).toHaveBeenCalledWith({
      user_salt: oldSalt,
      encrypted_vault_key: oldEncryptedVaultKey,
    });
  });
});

// =============================================================================
// 5. FORGOT PASSWORD — resetVaultKey
// =============================================================================

describe("Forgot Password: resetVaultKey", () => {
  const NEW_PASSWORD = "FreshStart!Pass789";

  beforeEach(() => {
    jest.clearAllMocks();
    sessionStorageMap.clear();
    clearVaultKey();

    encryptionKeysChain = createChainableMock();
    encryptionKeysChain.update.mockReturnValue(encryptionKeysChain);
    encryptionKeysChain.eq.mockResolvedValue({ error: null });
  });

  it("generates a new vault key and stores it in memory", async () => {
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    expect(isVaultUnlocked()).toBe(true);
    const key = getVaultKey();
    expect(key).toBeDefined();
    expect(key.type).toBe("secret");
  });

  it("writes new salt and wrapped key to database", async () => {
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    expect(encryptionKeysChain.update).toHaveBeenCalledWith(
      expect.objectContaining({
        user_salt: expect.any(String),
        encrypted_vault_key: expect.any(String),
      })
    );

    // Verify encrypted vault key format
    const updateArg = encryptionKeysChain.update.mock.calls[0][0];
    const parsed = JSON.parse(updateArg.encrypted_vault_key);
    expect(parsed).toHaveProperty("iv");
    expect(parsed).toHaveProperty("wrappedKey");
  });

  it("new password can unlock the reset vault key", async () => {
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    // Get stored values from mock
    const updateArg = encryptionKeysChain.update.mock.calls[0][0];
    const newSalt = updateArg.user_salt;
    const newEncryptedVaultKey = updateArg.encrypted_vault_key;

    // Derive master key with new password
    const masterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const unwrapped = await unwrapVaultKey(newEncryptedVaultKey, masterKey);

    // Should match the vault key now in memory
    const inMemoryRaw = await exportKeyRaw(getVaultKey());
    const unwrappedRaw = await exportKeyRaw(unwrapped);
    expect(unwrappedRaw).toEqual(inMemoryRaw);
  });

  it("old encrypted data cannot be decrypted with new vault key", async () => {
    // Create old vault key and encrypt data
    const oldVaultKey = await generateVaultKey();
    const secret = { password: "old-secret" };
    const encrypted = await encryptData(secret, oldVaultKey);

    // Reset vault (creates entirely new key)
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    // Try to decrypt old data with new key — should fail
    const newVaultKey = getVaultKey();
    await expect(decryptData(encrypted, newVaultKey)).rejects.toThrow();
  });

  it("stores new vault key in sessionStorage", async () => {
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    const stored = sessionStorageMap.get("nokslock_vk");
    expect(stored).toBeTruthy();
  });

  it("throws when database update fails", async () => {
    encryptionKeysChain.eq.mockResolvedValue({
      error: { message: "Update failed" },
    });

    await expect(
      resetVaultKey(NEW_PASSWORD, TEST_USER_ID)
    ).rejects.toThrow("Failed to reset vault keys");
  });

  it("new data can be encrypted and decrypted after reset", async () => {
    await resetVaultKey(NEW_PASSWORD, TEST_USER_ID);

    const newVaultKey = getVaultKey();
    const secret = { username: "fresh-start", password: "new-secret" };
    const encrypted = await encryptData(secret, newVaultKey);
    const decrypted = await decryptData(encrypted, newVaultKey);

    expect(decrypted).toEqual(secret);
  });
});

// =============================================================================
// 6. FULL END-TO-END FLOWS (no mocks on crypto, only DB mocked)
// =============================================================================

describe("Full E2E: Register → Login → Change Password → Login Again", () => {
  it("user can log in after changing password via settings", async () => {
    const OLD_PASSWORD = "OldP@ss123";
    const NEW_PASSWORD = "NewP@ss456";
    const userId = "user-e2e-001";

    // --- STEP 1: REGISTRATION ---
    // Simulate initializeVaultKey storing keys
    const regSalt = generateUserSalt();
    const regMasterKey = await deriveMasterKey(OLD_PASSWORD, regSalt);
    const vaultKey = await generateVaultKey();
    const regWrapped = await wrapVaultKey(vaultKey, regMasterKey);

    // Encrypt some data the user cares about
    const secrets = [
      { site: "google.com", pass: "g00gle!" },
      { site: "bank.com", pass: "b@nk$afe" },
    ];
    const encryptedSecrets = await Promise.all(
      secrets.map((s) => encryptData(s, vaultKey))
    );

    // --- STEP 2: LOGIN with old password ---
    const loginMasterKey = await deriveMasterKey(OLD_PASSWORD, regSalt);
    const unlockedVaultKey = await unwrapVaultKey(regWrapped, loginMasterKey);

    // Verify data is accessible
    for (let i = 0; i < secrets.length; i++) {
      const decrypted = await decryptData(encryptedSecrets[i], unlockedVaultKey);
      expect(decrypted).toEqual(secrets[i]);
    }

    // --- STEP 3: CHANGE PASSWORD (re-wrap vault key) ---
    const newSalt = generateUserSalt();
    const newMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const newWrapped = await wrapVaultKey(unlockedVaultKey, newMasterKey);

    // --- STEP 4: LOGIN with new password ---
    const newLoginMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const reUnlockedVaultKey = await unwrapVaultKey(newWrapped, newLoginMasterKey);

    // Verify same vault key
    const originalRaw = await exportKeyRaw(vaultKey);
    const reUnlockedRaw = await exportKeyRaw(reUnlockedVaultKey);
    expect(reUnlockedRaw).toEqual(originalRaw);

    // Verify data is STILL accessible
    for (let i = 0; i < secrets.length; i++) {
      const decrypted = await decryptData(encryptedSecrets[i], reUnlockedVaultKey);
      expect(decrypted).toEqual(secrets[i]);
    }
  });

  it("old password fails after password change", async () => {
    const OLD_PASSWORD = "OldP@ss123";
    const NEW_PASSWORD = "NewP@ss456";

    // Registration
    const salt = generateUserSalt();
    const masterKey = await deriveMasterKey(OLD_PASSWORD, salt);
    const vaultKey = await generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    // Password change — re-wrap with new password
    const unlockedKey = await unwrapVaultKey(wrapped, masterKey);
    const newSalt = generateUserSalt();
    const newMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const newWrapped = await wrapVaultKey(unlockedKey, newMasterKey);

    // Try to login with OLD password + NEW salt → should fail
    const oldMasterKeyNewSalt = await deriveMasterKey(OLD_PASSWORD, newSalt);
    await expect(
      unwrapVaultKey(newWrapped, oldMasterKeyNewSalt)
    ).rejects.toThrow();
  });

  it("forgot password: vault key is regenerated, old data is lost", async () => {
    const OLD_PASSWORD = "OldP@ss123";
    const NEW_PASSWORD = "ResetP@ss789";

    // Registration — create vault and encrypt data
    const salt = generateUserSalt();
    const masterKey = await deriveMasterKey(OLD_PASSWORD, salt);
    const vaultKey = await generateVaultKey();
    await wrapVaultKey(vaultKey, masterKey);

    const secret = { bank_pin: "1234" };
    const encrypted = await encryptData(secret, vaultKey);

    // Forgot password — generate entirely new vault key
    const newSalt = generateUserSalt();
    const newMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const newVaultKey = await generateVaultKey();
    const newWrapped = await wrapVaultKey(newVaultKey, newMasterKey);

    // Login with new password — vault unlocks
    const loginMasterKey = await deriveMasterKey(NEW_PASSWORD, newSalt);
    const unlockedKey = await unwrapVaultKey(newWrapped, loginMasterKey);
    expect(unlockedKey).toBeDefined();

    // But old encrypted data cannot be decrypted
    await expect(decryptData(encrypted, unlockedKey)).rejects.toThrow();

    // New data works fine
    const newSecret = { bank_pin: "5678" };
    const newEncrypted = await encryptData(newSecret, unlockedKey);
    const decrypted = await decryptData(newEncrypted, unlockedKey);
    expect(decrypted).toEqual(newSecret);
  });
});

// =============================================================================
// 7. EDGE CASES & SECURITY
// =============================================================================

describe("Edge Cases & Security", () => {
  beforeEach(() => {
    clearVaultKey();
    sessionStorageMap.clear();
  });

  it("getVaultKey throws when vault is locked", () => {
    expect(() => getVaultKey()).toThrow("Vault is locked");
  });

  it("isVaultUnlocked returns false when vault is locked", () => {
    expect(isVaultUnlocked()).toBe(false);
  });

  it("clearVaultKey removes key from memory and sessionStorage", async () => {
    // Set up vault key in memory
    encryptionKeysChain = createChainableMock();
    await initializeVaultKey(TEST_PASSWORD, TEST_USER_ID);

    expect(isVaultUnlocked()).toBe(true);
    expect(sessionStorageMap.has("nokslock_vk")).toBe(true);

    clearVaultKey();

    expect(isVaultUnlocked()).toBe(false);
    expect(sessionStorageMap.has("nokslock_vk")).toBe(false);
  });

  it("password with special characters works for full flow", async () => {
    const specialPassword = "p@$$w0rd!#%^&*()_+🔐";

    const salt = generateUserSalt();
    const masterKey = await deriveMasterKey(specialPassword, salt);
    const vaultKey = await generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    // Re-derive and unwrap
    const masterKey2 = await deriveMasterKey(specialPassword, salt);
    const unwrapped = await unwrapVaultKey(wrapped, masterKey2);

    const originalRaw = await exportKeyRaw(vaultKey);
    const unwrappedRaw = await exportKeyRaw(unwrapped);
    expect(unwrappedRaw).toEqual(originalRaw);
  });

  it("empty password still works cryptographically (validation is separate)", async () => {
    const salt = generateUserSalt();
    const masterKey = await deriveMasterKey("", salt);
    const vaultKey = await generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    const masterKey2 = await deriveMasterKey("", salt);
    const unwrapped = await unwrapVaultKey(wrapped, masterKey2);

    expect(unwrapped).toBeDefined();
  });

  it("very long password works correctly", async () => {
    const longPassword = "A".repeat(10_000) + "1!a";

    const salt = generateUserSalt();
    const masterKey = await deriveMasterKey(longPassword, salt);
    const vaultKey = await generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    const masterKey2 = await deriveMasterKey(longPassword, salt);
    const unwrapped = await unwrapVaultKey(wrapped, masterKey2);

    const originalRaw = await exportKeyRaw(vaultKey);
    const unwrappedRaw = await exportKeyRaw(unwrapped);
    expect(unwrappedRaw).toEqual(originalRaw);
  });

  it("multiple password changes in sequence preserve vault key", async () => {
    const passwords = ["First1!", "Second2@", "Third3#", "Fourth4$"];

    // Start: generate vault key with first password
    let currentSalt = generateUserSalt();
    const currentMasterKey = await deriveMasterKey(passwords[0], currentSalt);
    const vaultKey = await generateVaultKey();
    let currentWrapped = await wrapVaultKey(vaultKey, currentMasterKey);

    // Change password multiple times
    for (let i = 1; i < passwords.length; i++) {
      // Unwrap with current password
      const currentMK = await deriveMasterKey(passwords[i - 1], currentSalt);
      const unwrapped = await unwrapVaultKey(currentWrapped, currentMK);

      // Re-wrap with new password
      const newSalt = generateUserSalt();
      const newMK = await deriveMasterKey(passwords[i], newSalt);
      currentWrapped = await wrapVaultKey(unwrapped, newMK);
      currentSalt = newSalt;
    }

    // Final login with last password
    const finalMK = await deriveMasterKey(
      passwords[passwords.length - 1],
      currentSalt
    );
    const finalUnwrapped = await unwrapVaultKey(currentWrapped, finalMK);

    // Should still be the original vault key
    const originalRaw = await exportKeyRaw(vaultKey);
    const finalRaw = await exportKeyRaw(finalUnwrapped);
    expect(finalRaw).toEqual(originalRaw);
  });
});
