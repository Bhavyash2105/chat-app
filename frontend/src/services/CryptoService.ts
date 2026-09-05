/**
 * ════════════════════════════════════════════════════════════════════════════════
 * CRITICAL SECURITY NOTICE
 * ════════════════════════════════════════════════════════════════════════════════
 *
 * This file handles raw cryptographic key material, including:
 *   - Curve25519 private keys (base64)
 *   - AES symmetric keys (raw bytes)
 *   - Plaintext message content
 *
 * NEVER add console.log() calls that output ANY of the following:
 *   - privateKey (any format)
 *   - rawAesKey, plaintextBuf, decryptedBuf contents
 *   - plaintext strings (message content)
 *   - password values
 *   - mnemonic phrases / recovery seeds
 *
 * If you need to debug, use the Logger utility (services/Logger.ts) which:
 *   - Only logs in development mode
 *   - Logs lengths/hashes instead of raw values
 *   - Never exposes plaintext or key bytes
 * ════════════════════════════════════════════════════════════════════════════════
 */

const AES_ALGO = { name: "AES-GCM", length: 256 };
const PBKDF2_ITERATIONS = 600000;

export interface EncryptedPrivateKeyBundle {
    encryptedData: string;
    iv: string;
    salt: string;
}

/**
 * Encrypted payload for a private key bundle (a JSON string containing the
 * Curve25519 private key). Used for at-rest encryption in IndexedDB and for
 * the recovery blob. Message encryption itself is handled by the Double
 * Ratchet (see SessionRatchetService).
 */
export interface EncryptedKeyBundleInput {
    /** JSON-serialized Curve25519 private key bundle (not PKCS8 — no RSA) */
    privateKeyBundleJson: string;
}

function bufToBase64(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuf(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

class CryptoService {

    private async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const passwordKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
            passwordKey,
            AES_ALGO,
            false,
            ["encrypt", "decrypt"]
        );
    }

async encryptPrivateKey(privateKeyBundleJson: string, password: string): Promise<EncryptedPrivateKeyBundle> {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const derivedKey = await this.deriveKeyFromPassword(password, salt);
        const encryptedBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            derivedKey,
            new TextEncoder().encode(privateKeyBundleJson)
        );
        return {
            encryptedData: bufToBase64(encryptedBuf),
            iv: bufToBase64(iv.buffer),
            salt: bufToBase64(salt.buffer),
        };
    }

    // Throws on wrong password (AES-GCM auth tag check fails) — caller MUST catch this, it's the new-device trigger
    async decryptPrivateKey(bundle: EncryptedPrivateKeyBundle, password: string): Promise<string> {
        const salt = new Uint8Array(base64ToBuf(bundle.salt));
        const derivedKey = await this.deriveKeyFromPassword(password, salt);
        const decryptedBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToBuf(bundle.iv) },
            derivedKey,
            base64ToBuf(bundle.encryptedData)
        );
        return new TextDecoder().decode(decryptedBuf);
    }
}

const cryptoService = new CryptoService();
export default cryptoService;

