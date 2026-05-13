"use server";

import { createSupabaseAdminClient } from "@/lib/supabase/admin-client";

export async function saveInitialEncryptionKeys(
  userId: string,
  userSalt: string,
  encryptedVaultKey: string,
): Promise<void> {
  const supabase = createSupabaseAdminClient();

  const { error } = await supabase.from("user_encryption_keys").insert({
    user_id: userId,
    user_salt: userSalt,
    encrypted_vault_key: encryptedVaultKey,
  });

  if (error) {
    throw new Error(`Failed to save encryption keys: ${error.message}`);
  }
}
