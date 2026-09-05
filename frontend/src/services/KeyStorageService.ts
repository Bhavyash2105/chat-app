const DB_NAME = "chatapp-keystore";
const DB_VERSION = 6;
const STORE_NAME = "privateKeys";
const SESSION_STORE_NAME = "ratchetSessions";
const IDENTITY_STORE_NAME = "identities";
const PREKEY_STORE_NAME = "ratchetPreKeys";
const SIGNED_PREKEY_STORE_NAME = "ratchetSignedPreKey";
const REGISTRATION_ID_STORE_NAME = "ratchetRegistrationId";
const SENT_MESSAGES_STORE_NAME = "sentMessages";
const LOCAL_CACHE_KEY_STORE_NAME = "localCacheKeys";
const DEVICE_ID_KEY = "chatapp_device_id";
const USER_INDEX = "byUserId";

/**
 * A pinned remote identity (public key) for a contact.
 * Used to reject silently-changed identity keys (replaces pure TOFU).
 * The identity key is stored as base64 (public key material, not secret).
 */
export interface StoredIdentityRecord {
    identifier: string;   // primary key — contact identifier (userId-deviceId)
    identityKey: string;  // base64 public identity key pinned for this contact
    createdAt: string;
    updatedAt: string;
}

export interface StoredKeyRecord {
    userId: string; // primary key — one active key record per user per device
    keyVersion: number;
    encryptedData: string;
    iv: string;
    salt: string;
    publicKey: string;
    createdAt: string;
}

/**
 * Session state stored in IndexedDB for the Double Ratchet.
 * The actual session data is encrypted at rest using AES-GCM
 * with a key derived from the ratchet store key.
 */
export interface StoredSessionRecord {
    userId: string;      // primary key — partner user's ID (userId-deviceId)
    deviceId: string;    // partner's device ID
    sessionData: string; // JSON-encrypted Signal Protocol session data
    createdAt: string;
    updatedAt: string;
}

/**
 * A Double Ratchet one-time pre-key persisted at rest.
 * Holds PRIVATE key material (encrypted) so the device can decrypt incoming
 * PreKeyWhisperMessages after a reload or logout/login.
 */
export interface StoredPreKeyRecord {
    userId: string;              // owner user id (part of composite key [userId, id])
    id: number;                  // pre-key id (part of composite key [userId, id])
    pubKey: string;              // base64 public key
    privKey: string;             // base64 private key (encrypted at rest by caller)
    createdAt: string;
}

/**
 * A Double Ratchet signed pre-key persisted at rest.
 * Holds PRIVATE key material (encrypted) needed to decrypt incoming
 * PreKeyWhisperMessages (type 3) after a reload.
 */
export interface StoredSignedPreKeyRecord {
    userId: string;              // owner user id (part of composite key [userId, id])
    id: number;                  // signed pre-key id (part of composite key [userId, id])
    pubKey: string;              // base64 public key
    privKey: string;             // base64 private key (encrypted at rest by caller)
    signature: string;           // base64 signature of the signed pre-key
    createdAt: string;
}

export interface StoredRegistrationIdRecord {
    userId: string;              // primary key — owner user id
    registrationId: number;
    createdAt: string;
}

/**
 * A sent message cached on the sender's device so the sender can render its own
 * plaintext without ever creating a ratchet self-session (which the Signal
 * library cannot decrypt). The plaintext is encrypted at rest by the caller
 * using a per-user local cache key.
 */
export interface StoredSentMessageRecord {
    messageId: string;   // primary key: temp client id or real server message UUID
    userId: string;      // owner sender user id
    encryptedPlaintext: string; // AES-GCM ciphertext of the plaintext
    iv: string;          // AES-GCM IV
    createdAt: string;
    updatedAt: string;
}

/**
 * Per-user AES-GCM key used to encrypt/decrypt the sent-message cache at rest.
 * Stored wrapped (encrypted) so it only decrypts on this device.
 */
export interface StoredLocalCacheKeyRecord {
    userId: string;              // primary key — owner user id
    encryptedKey: string;        // encrypted raw AES-256 key bytes
    iv: string;                  // AES-GCM IV used to wrap the key
    createdAt: string;
}

class KeyStorageService {
    private dbPromise: Promise<IDBDatabase> | null = null;

    private openDb(): Promise<IDBDatabase> {
        if (this.dbPromise) return this.dbPromise;
        this.dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = (event) => {
                const db = request.result;
                const oldVersion = event.oldVersion;

                // Version 1: privateKeys store
                if (oldVersion < 1) {
                    if (!db.objectStoreNames.contains(STORE_NAME)) {
                        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
                    }
                }

// Version 2: ratchetSessions store
                if (oldVersion < 2) {
                    if (!db.objectStoreNames.contains(SESSION_STORE_NAME)) {
                        db.createObjectStore(SESSION_STORE_NAME, { keyPath: "userId" });
                    }
                }

// Version 3: identities store (pinned remote identity keys)
                if (oldVersion < 3) {
                    if (!db.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
                        db.createObjectStore(IDENTITY_STORE_NAME, { keyPath: "identifier" });
                    }
                }

// Version 4: Double Ratchet pre-keys, signed pre-key, registration ID
                // These hold PRIVATE key material (encrypted at rest) needed to decrypt
                // incoming PreKeyWhisperMessages after a reload. Without them the receiver
                // can never build the session for a type-3 message.
                if (oldVersion < 4) {
                    if (!db.objectStoreNames.contains(PREKEY_STORE_NAME)) {
                        db.createObjectStore(PREKEY_STORE_NAME, { keyPath: ["userId", "id"] });
                    }
                    if (!db.objectStoreNames.contains(SIGNED_PREKEY_STORE_NAME)) {
                        db.createObjectStore(SIGNED_PREKEY_STORE_NAME, { keyPath: ["userId", "id"] });
                    }
                    if (!db.objectStoreNames.contains(REGISTRATION_ID_STORE_NAME)) {
                        db.createObjectStore(REGISTRATION_ID_STORE_NAME, { keyPath: "userId" });
                    }
                }

                // Version 5: Scope ratchet keys by userId so multiple accounts on the
                // same device don't overwrite each other's private pre-keys (which is
                // what caused "Cannot decrypt" after logout/login). Composite keys are
                // [userId, id] for pre-keys/signed pre-key, and userId for registration.
                if (oldVersion < 5) {
                    // Recreate stores with composite keys (drop old numeric-only versions).
                    if (db.objectStoreNames.contains(PREKEY_STORE_NAME)) {
                        db.deleteObjectStore(PREKEY_STORE_NAME);
                    }
                    if (db.objectStoreNames.contains(SIGNED_PREKEY_STORE_NAME)) {
                        db.deleteObjectStore(SIGNED_PREKEY_STORE_NAME);
                    }
                    if (db.objectStoreNames.contains(REGISTRATION_ID_STORE_NAME)) {
                        db.deleteObjectStore(REGISTRATION_ID_STORE_NAME);
                    }
db.createObjectStore(PREKEY_STORE_NAME, { keyPath: ["userId", "id"] });
                    db.createObjectStore(SIGNED_PREKEY_STORE_NAME, { keyPath: ["userId", "id"] });
                    db.createObjectStore(REGISTRATION_ID_STORE_NAME, { keyPath: "userId" });
                }

                // Version 6: sent-message cache (sender's own plaintext, encrypted at
                // rest) + per-user local cache key. The sender never creates a ratchet
                // self-session (which the Signal library cannot decrypt), so it renders
                // its own sent messages from this local cache instead.
                if (oldVersion < 6) {
                    if (!db.objectStoreNames.contains(SENT_MESSAGES_STORE_NAME)) {
                        db.createObjectStore(SENT_MESSAGES_STORE_NAME, { keyPath: "messageId" });
                    }
                    if (!db.objectStoreNames.contains(LOCAL_CACHE_KEY_STORE_NAME)) {
                        db.createObjectStore(LOCAL_CACHE_KEY_STORE_NAME, { keyPath: "userId" });
                    }
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
        return this.dbPromise;
    }

    // ── Device ID ──

    /**
     * Get or create a persistent random device ID for this browser.
     * Stored in localStorage (not IndexedDB) so it survives IndexedDB clear.
     */
    getOrCreateDeviceId(): string {
        let deviceId = localStorage.getItem(DEVICE_ID_KEY);
        if (!deviceId) {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            deviceId = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
            localStorage.setItem(DEVICE_ID_KEY, deviceId);
        }
        return deviceId;
    }

    // ── Key Record ──

    async saveKeyRecord(record: StoredKeyRecord): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async getKeyRecord(userId: string): Promise<StoredKeyRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readonly");
            const req = tx.objectStore(STORE_NAME).get(userId);
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
        });
    }

    async deleteKeyRecord(userId: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).delete(userId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Ratchet Session Storage ──

    async saveSession(record: StoredSessionRecord): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SESSION_STORE_NAME, "readwrite");
            tx.objectStore(SESSION_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async loadSession(userId: string): Promise<StoredSessionRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SESSION_STORE_NAME, "readonly");
            const req = tx.objectStore(SESSION_STORE_NAME).get(userId);
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
        });
    }

    async deleteSession(userId: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SESSION_STORE_NAME, "readwrite");
            tx.objectStore(SESSION_STORE_NAME).delete(userId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

/**
     * Clear all session data (e.g., on logout).
     */
    async clearAllSessions(): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SESSION_STORE_NAME, "readwrite");
            tx.objectStore(SESSION_STORE_NAME).clear();
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Double Ratchet Pre-Key Storage ──

    /**
     * Persist a one-time pre-key (private key material, encrypted at rest).
     * Needed to decrypt incoming PreKeyWhisperMessages after a reload.
     */
async savePreKey(record: StoredPreKeyRecord): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] savePreKey userId=${record.userId} id=${record.id} pubKeyHash=${record.pubKey.length}chars privKeyEncrypted=${record.privKey.length > 0}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(PREKEY_STORE_NAME, "readwrite");
            tx.objectStore(PREKEY_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async loadPreKey(userId: string, id: number): Promise<StoredPreKeyRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(PREKEY_STORE_NAME, "readonly");
            const req = tx.objectStore(PREKEY_STORE_NAME).get([userId, id]);
            req.onsuccess = () => {
                const r = req.result ?? null;
                console.log(`[KEYSTORE] loadPreKey userId=${userId} id=${id} found=${!!r}`);
                resolve(r);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async getAllPreKeys(userId: string): Promise<StoredPreKeyRecord[]> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(PREKEY_STORE_NAME, "readonly");
            const store = tx.objectStore(PREKEY_STORE_NAME);
            // Filter in-memory by userId (composite key starts with userId).
            const req = store.getAll();
            req.onsuccess = () => {
                const all: StoredPreKeyRecord[] = req.result ?? [];
                const r = all.filter(k => k.userId === userId);
                console.log(`[KEYSTORE] getAllPreKeys userId=${userId} count=${r.length}`);
                resolve(r);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async deletePreKey(userId: string, id: number): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] deletePreKey userId=${userId} id=${id}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(PREKEY_STORE_NAME, "readwrite");
            tx.objectStore(PREKEY_STORE_NAME).delete([userId, id]);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async clearAllPreKeys(userId: string): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] clearAllPreKeys userId=${userId}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(PREKEY_STORE_NAME, "readwrite");
            const store = tx.objectStore(PREKEY_STORE_NAME);
            const delReq = store.getAll();
            delReq.onsuccess = () => {
                const all: StoredPreKeyRecord[] = delReq.result ?? [];
                for (const k of all) {
                    if (k.userId === userId) {
                        store.delete([k.userId, k.id]);
                    }
                }
            };
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Double Ratchet Signed Pre-Key Storage ──

    /**
     * Persist the signed pre-key (private key material, encrypted at rest).
     * Needed to decrypt incoming PreKeyWhisperMessages after a reload.
     */
    async saveSignedPreKey(record: StoredSignedPreKeyRecord): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] saveSignedPreKey userId=${record.userId} id=${record.id}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SIGNED_PREKEY_STORE_NAME, "readwrite");
            tx.objectStore(SIGNED_PREKEY_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async loadSignedPreKey(userId: string, id: number): Promise<StoredSignedPreKeyRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SIGNED_PREKEY_STORE_NAME, "readonly");
            const req = tx.objectStore(SIGNED_PREKEY_STORE_NAME).get([userId, id]);
            req.onsuccess = () => {
                const r = req.result ?? null;
                console.log(`[KEYSTORE] loadSignedPreKey userId=${userId} id=${id} found=${!!r}`);
                resolve(r);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async getAllSignedPreKeys(userId: string): Promise<StoredSignedPreKeyRecord[]> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SIGNED_PREKEY_STORE_NAME, "readonly");
            const req = tx.objectStore(SIGNED_PREKEY_STORE_NAME).getAll();
            req.onsuccess = () => {
                const all: StoredSignedPreKeyRecord[] = req.result ?? [];
                const r = all.filter(k => k.userId === userId);
                console.log(`[KEYSTORE] getAllSignedPreKeys userId=${userId} count=${r.length}`);
                resolve(r);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async deleteSignedPreKey(userId: string, id: number): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] deleteSignedPreKey userId=${userId} id=${id}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SIGNED_PREKEY_STORE_NAME, "readwrite");
            tx.objectStore(SIGNED_PREKEY_STORE_NAME).delete([userId, id]);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Double Ratchet Registration ID Storage ──

    async saveRegistrationId(record: StoredRegistrationIdRecord): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] saveRegistrationId userId=${record.userId}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(REGISTRATION_ID_STORE_NAME, "readwrite");
            tx.objectStore(REGISTRATION_ID_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async loadRegistrationId(userId: string): Promise<StoredRegistrationIdRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(REGISTRATION_ID_STORE_NAME, "readonly");
            const req = tx.objectStore(REGISTRATION_ID_STORE_NAME).get(userId);
            req.onsuccess = () => {
                const r = req.result ?? null;
                console.log(`[KEYSTORE] loadRegistrationId userId=${userId} found=${!!r}`);
                resolve(r);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async deleteRegistrationId(userId: string): Promise<void> {
        const db = await this.openDb();
        console.log(`[KEYSTORE] deleteRegistrationId userId=${userId}`);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(REGISTRATION_ID_STORE_NAME, "readwrite");
            tx.objectStore(REGISTRATION_ID_STORE_NAME).delete(userId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

// ── Sent Messages Cache (sender's own plaintext, encrypted at rest) ──

    /**
     * Persist the sender's own message plaintext (encrypted by the caller) keyed
     * by the real server message UUID. The sender NEVER creates a ratchet
     * self-session, so it renders its own sent messages from this cache.
     */
    async saveSentMessage(record: StoredSentMessageRecord): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readwrite");
            tx.objectStore(SENT_MESSAGES_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async getSentMessage(messageId: string): Promise<StoredSentMessageRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readonly");
            const req = tx.objectStore(SENT_MESSAGES_STORE_NAME).get(messageId);
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
        });
    }

    async deleteSentMessage(messageId: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readwrite");
            tx.objectStore(SENT_MESSAGES_STORE_NAME).delete(messageId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async rekeySentMessage(oldMessageId: string, newMessageId: string): Promise<boolean> {
        if (oldMessageId === newMessageId) return true;
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readwrite");
            const store = tx.objectStore(SENT_MESSAGES_STORE_NAME);
            const getReq = store.get(oldMessageId);
            let found = false;

            getReq.onsuccess = () => {
                const record = getReq.result as StoredSentMessageRecord | undefined;
                if (!record) return;
                found = true;
                store.put({
                    ...record,
                    messageId: newMessageId,
                    updatedAt: new Date().toISOString(),
                });
                store.delete(oldMessageId);
            };
            getReq.onerror = () => reject(getReq.error);
            tx.oncomplete = () => resolve(found);
            tx.onerror = () => reject(tx.error);
        });
    }

    async deleteExpiredTempSentMessages(userId: string, ttlMs: number): Promise<number> {
        const db = await this.openDb();
        const cutoff = Date.now() - ttlMs;
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readwrite");
            const store = tx.objectStore(SENT_MESSAGES_STORE_NAME);
            const cursorReq = store.openCursor();
            let deleted = 0;

            cursorReq.onsuccess = () => {
                const cursor = cursorReq.result;
                if (!cursor) return;
                const record = cursor.value as StoredSentMessageRecord;
                const timestamp = Date.parse(record.createdAt || record.updatedAt || '');
                if (
                    record.userId === userId &&
                    record.messageId.startsWith('temp-') &&
                    Number.isFinite(timestamp) &&
                    timestamp < cutoff
                ) {
                    cursor.delete();
                    deleted += 1;
                }
                cursor.continue();
            };
            cursorReq.onerror = () => reject(cursorReq.error);
            tx.oncomplete = () => resolve(deleted);
            tx.onerror = () => reject(tx.error);
        });
    }

    async clearAllSentMessages(userId: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(SENT_MESSAGES_STORE_NAME, "readwrite");
            const store = tx.objectStore(SENT_MESSAGES_STORE_NAME);
            const cursorReq = store.openCursor();
            cursorReq.onsuccess = () => {
                const cursor = cursorReq.result;
                if (!cursor) return;
                const record = cursor.value as StoredSentMessageRecord;
                if (record.userId === userId) {
                    cursor.delete();
                }
                cursor.continue();
            };
            cursorReq.onerror = () => reject(cursorReq.error);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Local Cache Key (per-user, device-scoped) ──

    /**
     * Persist the per-user AES-GCM key used to encrypt the sent-message cache at
     * rest. The key itself is stored encrypted (wrapped by the user's Curve25519
     * store key material) so it only decrypts on this device.
     */
    async saveLocalCacheKey(record: StoredLocalCacheKeyRecord): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(LOCAL_CACHE_KEY_STORE_NAME, "readwrite");
            tx.objectStore(LOCAL_CACHE_KEY_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async getLocalCacheKey(userId: string): Promise<StoredLocalCacheKeyRecord | null> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(LOCAL_CACHE_KEY_STORE_NAME, "readonly");
            const req = tx.objectStore(LOCAL_CACHE_KEY_STORE_NAME).get(userId);
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
        });
    }

    async deleteLocalCacheKey(userId: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(LOCAL_CACHE_KEY_STORE_NAME, "readwrite");
            tx.objectStore(LOCAL_CACHE_KEY_STORE_NAME).delete(userId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ── Pinned Identity Storage ──

    /**
     * Persist a pinned remote identity public key for a contact.
     * Identity keys are public material (base64), so no encryption at rest is needed.
     */
    async saveIdentity(record: StoredIdentityRecord): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
            tx.objectStore(IDENTITY_STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    /**
     * Load all pinned identities for this device.
     */
    async getAllIdentities(): Promise<StoredIdentityRecord[]> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(IDENTITY_STORE_NAME, "readonly");
            const req = tx.objectStore(IDENTITY_STORE_NAME).getAll();
            req.onsuccess = () => resolve(req.result ?? []);
            req.onerror = () => reject(req.error);
        });
    }

    /**
     * Delete a single pinned identity.
     */
    async deleteIdentity(identifier: string): Promise<void> {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
            tx.objectStore(IDENTITY_STORE_NAME).delete(identifier);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }
}

const keyStorageService = new KeyStorageService();
export default keyStorageService;

