import CryptoService from "./CryptoService";
import KeyStorageService, { StoredKeyRecord } from "./KeyStorageService";
import SessionRatchetService from "./SessionRatchetService";
import { KeyHelper } from '@privacyresearch/libsignal-protocol-typescript';

export type NewDeviceReason = "no-local-key" | "decrypt-failed";

export interface LoadResult {
    status: "ok" | "new-device";
    reason?: NewDeviceReason;
}

/** Extended key record that includes the Curve25519 identity key for ratchet */
export interface ExtendedStoredKeyRecord extends StoredKeyRecord {
    /** Base64-encoded Curve25519 public key (for X3DH session init) */
    curve25519PublicKey?: string;
    /** Base64-encoded Curve25519 private key */
    curve25519PrivateKey?: string;
}

class KeyManagementService {
    private curve25519PrivateKeyCache: string | null = null;
    private currentUserId: string | null = null;

    /**
     * Generate a proper Curve25519 (X25519) keypair using the Signal Protocol library.
     * This is the only identity keypair used — X3DH and the Double Ratchet both
     * rely on Curve25519.
     */
    private async generateProperCurve25519KeyPair(): Promise<{ publicKey: string; privateKey: string }> {
        const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
        return {
            publicKey: KeyManagementService.arrayBufferToBase64(identityKeyPair.pubKey),
            privateKey: KeyManagementService.arrayBufferToBase64(identityKeyPair.privKey),
        };
    }

private static arrayBufferToBase64(buf: ArrayBuffer): string {
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    /** SHA-256 hash prefix of a value for safe debug logging (never logs raw keys). */
    private async _hashForLog(value: string): Promise<string> {
        try {
            const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
            return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
        } catch {
            return `${value.length}chars`;
        }
    }

    // Call right after successful signup. Returns Curve25519 publicKey (base64).
    // The private key is stored in the encrypted bundle (password-protected).
    async initializeOnSignup(userId: string, password: string): Promise<string> {
        console.log(`[KEYMGMT] initializeOnSignup START userId=${userId} deviceId=${KeyStorageService.getOrCreateDeviceId()}`);
        // Generate a proper Curve25519 identity keypair for the ratchet using Signal library
        const curve25519 = await this.generateProperCurve25519KeyPair();
        console.log(`[KEYMGMT] identity keypair generated`, {
            pubKeyLen: curve25519.publicKey.length,
            pubKeyHash: await this._hashForLog(curve25519.publicKey),
        });

        // Encrypt the Curve25519 private key as a password-protected bundle
        const combinedPrivateKey = JSON.stringify({
            curve25519PrivateKey: curve25519.privateKey,
        });
        const encryptedCombined = await CryptoService.encryptPrivateKey(combinedPrivateKey, password);
        console.log(`[KEYMGMT] private key bundle encrypted at rest`);

        const record: ExtendedStoredKeyRecord = {
            userId,
            keyVersion: 1,
            encryptedData: encryptedCombined.encryptedData,
            iv: encryptedCombined.iv,
            salt: encryptedCombined.salt,
            publicKey: curve25519.publicKey,
            curve25519PublicKey: curve25519.publicKey,
            curve25519PrivateKey: undefined, // stored inside the encrypted bundle
            createdAt: new Date().toISOString(),
        };
        await KeyStorageService.saveKeyRecord(record as StoredKeyRecord);
        console.log(`[KEYMGMT] key record saved to IndexedDB for userId=${userId}`);

        this.curve25519PrivateKeyCache = curve25519.privateKey;
        this.currentUserId = userId;
        console.log(`[KEYMGMT] initializeOnSignup DONE userId=${userId} privKeyCached=${!!this.curve25519PrivateKeyCache}`);
        return curve25519.publicKey;
    }

// Call right after successful signin. On "new-device", caller shows disclaimer dialog
    // then calls initializeOnSignup again (which overwrites the local record with a fresh keypair).
    async loadOnSignIn(userId: string, password: string): Promise<LoadResult> {
        console.log(`[KEYMGMT] loadOnSignIn START userId=${userId} deviceId=${KeyStorageService.getOrCreateDeviceId()}`);
        const record = await KeyStorageService.getKeyRecord(userId);
        if (!record) {
            console.log(`[KEYMGMT] loadOnSignIn: NO local key record for userId=${userId} → new-device(no-local-key)`);
            return { status: "new-device", reason: "no-local-key" };
        }
        console.log(`[KEYMGMT] loadOnSignIn: key record FOUND for userId=${userId}`, {
            keyVersion: record.keyVersion,
            pubKeyHash: await this._hashForLog(record.publicKey),
        });

        try {
            const decryptedBundle = await CryptoService.decryptPrivateKey(
                { encryptedData: record.encryptedData, iv: record.iv, salt: record.salt },
                password
            );
            console.log(`[KEYMGMT] loadOnSignIn: private bundle decrypted successfully`);

            // Parse the bundle to extract the Curve25519 private key
            let curve25519PrivateKey: string | undefined;

            try {
                const parsed = JSON.parse(decryptedBundle);
                curve25519PrivateKey = parsed.curve25519PrivateKey;
            } catch {
                // If the bundle is not JSON, treat it as a raw private key string
                curve25519PrivateKey = decryptedBundle;
            }

            this.curve25519PrivateKeyCache = curve25519PrivateKey || null;
            const curve25519PublicKeyCache = (record as ExtendedStoredKeyRecord).curve25519PublicKey || null;
            this.currentUserId = userId;
            console.log(`[KEYMGMT] loadOnSignIn: privKeyCached=${!!this.curve25519PrivateKeyCache} pubKeyCached=${!!curve25519PublicKeyCache}`);

            // Initialize the SessionRatchetService with the Curve25519 key
            if (this.curve25519PrivateKeyCache && curve25519PublicKeyCache) {
                const deviceId = KeyStorageService.getOrCreateDeviceId();
                try {
                    await SessionRatchetService.initialize(
                        userId,
                        this.curve25519PrivateKeyCache,
                        curve25519PublicKeyCache,
                        deviceId
                    );
                    console.log(`[KEYMGMT] SessionRatchetService.initialize OK for userId=${userId}`);
                } catch (error) {
                    // Ratchet initialization may fail if the library isn't installed yet
                    // Non-fatal — logs the error
                    console.warn('[KEYMGMT] SessionRatchetService initialization skipped:', error);
                }
            }

            console.log(`[KEYMGMT] loadOnSignIn DONE status=ok userId=${userId}`);
            return { status: "ok" };
        } catch (e) {
            console.log(`[KEYMGMT] loadOnSignIn: bundle decrypt FAILED for userId=${userId} → new-device(decrypt-failed)`, (e as Error).message);
            return { status: "new-device", reason: "decrypt-failed" };
        }
    }

    // Caller MUST verify oldPassword against the backend BEFORE calling this.
    // This only re-wraps the local private key bundle — it does not touch the server.
    async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
        const record = await KeyStorageService.getKeyRecord(userId);
        if (!record) throw new Error("No local private key — cannot re-encrypt for password change");

        const decryptedBundle = await CryptoService.decryptPrivateKey(
            { encryptedData: record.encryptedData, iv: record.iv, salt: record.salt },
            oldPassword
        );

        let curve25519PrivateKey: string | undefined;
        try {
            const parsed = JSON.parse(decryptedBundle);
            curve25519PrivateKey = parsed.curve25519PrivateKey;
        } catch {
            curve25519PrivateKey = decryptedBundle;
        }

        const newBundle = JSON.stringify({ curve25519PrivateKey });
        const reEncrypted = await CryptoService.encryptPrivateKey(newBundle, newPassword);

        await KeyStorageService.saveKeyRecord({
            ...record,
            encryptedData: reEncrypted.encryptedData,
            iv: reEncrypted.iv,
            salt: reEncrypted.salt,
        });

        // Update cache
        if (curve25519PrivateKey) {
            this.curve25519PrivateKeyCache = curve25519PrivateKey;
        }
    }

    // Same as regenerateKeys but DOES NOT persist to IndexedDB — returns the record for
    // the caller to persist ONLY after all network calls succeed. This is critical for
    // atomicity: if blob upload or public key upload fails, the old key record in IndexedDB
    // must remain intact so the user can still decrypt messages.
    // Returns { publicKey (base64), record (ExtendedStoredKeyRecord) }.
    async regenerateKeysWithoutPersist(userId: string, password: string): Promise<{ publicKey: string; record: ExtendedStoredKeyRecord }> {
        const existing = await KeyStorageService.getKeyRecord(userId);
        const nextVersion = existing ? existing.keyVersion + 1 : 1;

        const curve25519 = await this.generateProperCurve25519KeyPair();

        const combinedPrivateKey = JSON.stringify({
            curve25519PrivateKey: curve25519.privateKey,
        });
        const encrypted = await CryptoService.encryptPrivateKey(combinedPrivateKey, password);

        const record: ExtendedStoredKeyRecord = {
            userId,
            keyVersion: nextVersion,
            encryptedData: encrypted.encryptedData,
            iv: encrypted.iv,
            salt: encrypted.salt,
            publicKey: curve25519.publicKey,
            curve25519PublicKey: curve25519.publicKey,
            createdAt: new Date().toISOString(),
        };

        // Cache the new keys in memory
        this.curve25519PrivateKeyCache = curve25519.privateKey;
        this.currentUserId = userId;

        return { publicKey: curve25519.publicKey, record };
    }

    // Persist a key record to IndexedDB (called only after network calls confirm success).
    async persistKeyRecord(record: ExtendedStoredKeyRecord): Promise<void> {
        await KeyStorageService.saveKeyRecord(record as StoredKeyRecord);
    }

    // Rollback: restore a previously-saved key record + re-load it into the cache.
    // Call this if a network call fails after regenerateKeysWithoutPersist().
    async restoreFromKeyRecord(record: ExtendedStoredKeyRecord, password: string): Promise<void> {
        await KeyStorageService.saveKeyRecord(record as StoredKeyRecord);
        const decryptedBundle = await CryptoService.decryptPrivateKey(
            { encryptedData: record.encryptedData, iv: record.iv, salt: record.salt },
            password
        );

        let curve25519PrivateKey: string | undefined;
        try {
            const parsed = JSON.parse(decryptedBundle);
            curve25519PrivateKey = parsed.curve25519PrivateKey;
        } catch {
            curve25519PrivateKey = decryptedBundle;
        }

        if (curve25519PrivateKey) {
            this.curve25519PrivateKeyCache = curve25519PrivateKey;
        }
        this.currentUserId = record.userId;
    }

    // Generates a brand-new keypair AND persists immediately.
    // Used by initializeOnSignup where there is no old key to roll back to.
    async regenerateKeys(userId: string, password: string): Promise<string> {
        const existing = await KeyStorageService.getKeyRecord(userId);
        const nextVersion = existing ? existing.keyVersion + 1 : 1;

        const curve25519 = await this.generateProperCurve25519KeyPair();

        const combinedPrivateKey = JSON.stringify({
            curve25519PrivateKey: curve25519.privateKey,
        });
        const encrypted = await CryptoService.encryptPrivateKey(combinedPrivateKey, password);

        const record: ExtendedStoredKeyRecord = {
            userId,
            keyVersion: nextVersion,
            encryptedData: encrypted.encryptedData,
            iv: encrypted.iv,
            salt: encrypted.salt,
            publicKey: curve25519.publicKey,
            curve25519PublicKey: curve25519.publicKey,
            createdAt: new Date().toISOString(),
        };
        await KeyStorageService.saveKeyRecord(record as StoredKeyRecord);

        this.curve25519PrivateKeyCache = curve25519.privateKey;
        this.currentUserId = userId;
        return curve25519.publicKey;
    }

    getCurve25519PrivateKey(): string | null {
        return this.curve25519PrivateKeyCache;
    }

    getCurrentUserId(): string | null {
        return this.currentUserId;
    }

    /**
     * Upload the pre-key bundle to the server for X3DH session initiation.
     * Should be called after signup (after public key upload) and periodically
     * to replenish one-time pre-keys.
     */
    async uploadPreKeyBundle(authToken: string, publicKeyOverride?: string): Promise<void> {
        if (!this.curve25519PrivateKeyCache) {
            throw new Error('Curve25519 key not loaded — cannot generate pre-key bundle');
        }
        const deviceId = KeyStorageService.getOrCreateDeviceId();
        if (!this.currentUserId) {
            throw new Error('User not loaded — cannot initialize SessionRatchetService');
        }
        const record = await KeyStorageService.getKeyRecord(this.currentUserId);
        const publicKey = publicKeyOverride || (record as ExtendedStoredKeyRecord)?.curve25519PublicKey;
        if (!publicKey) {
            throw new Error('Curve25519 public key not loaded — cannot initialize SessionRatchetService');
        }
        await SessionRatchetService.initialize(
            this.currentUserId,
            this.curve25519PrivateKeyCache,
            publicKey,
            deviceId
        );
        const bundle = await SessionRatchetService.generatePreKeyBundle(100);
        await SessionRatchetService.uploadPreKeyBundle(bundle, authToken);
    }

    // Deliberately does NOT delete the IndexedDB record — it's ciphertext at rest and needed
    // so the same device can decrypt on next login without a false "new-device" trigger.
    clearOnLogout(): void {
        this.curve25519PrivateKeyCache = null;
        this.currentUserId = null;
        SessionRatchetService.clearAllSessions().catch(() => {});
    }
}

const keyManagementService = new KeyManagementService();
export default keyManagementService;
