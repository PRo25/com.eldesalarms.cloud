import {
  createCipheriv, createDecipheriv, randomBytes, scryptSync,
} from 'node:crypto';

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SCRYPT_COST = 32_768;

export type EncryptedSecret = {
  ciphertext: string;
  salt: string;
  iv: string;
  authTag: string;
};

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  if (passphrase.length < 12) {
    throw new Error('Choose an encryption passphrase with at least 12 characters.');
  }

  return scryptSync(passphrase, salt, KEY_LENGTH, {
    N: SCRYPT_COST,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
}

export function encryptSecret(plaintext: string, passphrase: string): EncryptedSecret {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);
  const plaintextBuffer = Buffer.from(plaintext, 'utf8');

  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintextBuffer),
      cipher.final(),
    ]);

    return {
      ciphertext: ciphertext.toString('base64'),
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
    };
  } finally {
    key.fill(0);
    plaintextBuffer.fill(0);
  }
}

export function decryptSecret(encrypted: EncryptedSecret, passphrase: string): string {
  const salt = Buffer.from(encrypted.salt, 'base64');
  const iv = Buffer.from(encrypted.iv, 'base64');
  const authTag = Buffer.from(encrypted.authTag, 'base64');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
  if (
    salt.length !== SALT_LENGTH
    || iv.length !== IV_LENGTH
    || authTag.length !== AUTH_TAG_LENGTH
    || ciphertext.length === 0
  ) {
    throw new Error('The saved ELDES token is invalid. Repair the device to sign in again.');
  }

  const key = deriveKey(passphrase, salt);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    try {
      return plaintext.toString('utf8');
    } finally {
      plaintext.fill(0);
    }
  } catch (error) {
    const reason = error instanceof Error
      ? 'The passphrase may be incorrect.'
      : 'The saved token may be damaged.';
    throw new Error(`Could not decrypt the saved ELDES token. ${reason}`);
  } finally {
    key.fill(0);
  }
}
