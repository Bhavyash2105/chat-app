/**
 * ════════════════════════════════════════════════════════════════════════════════
 * SessionRatchetService — Double Ratchet (X3DH + DH ratchet + symmetric ratchet)
 * ════════════════════════════════════════════════════════════════════════════════
 *
 * This service manages the full Signal Protocol Double Ratchet lifecycle:
 *   1. Pre-key bundle generation & upload
 *   2. X3DH session initiation (from a recipient's pre-key bundle)
 *   3. Per-message encrypt/decrypt via SessionCipher
 *   4. Ratchet key rotation & old key deletion (handled by the library)
 *   5. MAX_SKIP = 100 for out-of-order message buffering
 *
 * This service owns the message encryption path for the app: Double Ratchet.
 * Curve25519 identity keys are used throughout for X3DH + ratchet.
 *
 * Dependencies:
 *   - @privacyresearch/libsignal-protocol-typescript (Signal Protocol)
 *   - KeyStorageService (session persistence, encrypted at rest)
 *   - CryptoService (AES-GCM for encrypting session data at rest)
 *
 * NEVER log session keys, chain keys, or plaintext message content.
 * ════════════════════════════════════════════════════════════════════════════════
 */

import {
    SignalProtocolAddress,
    SessionBuilder,
    SessionCipher,
    KeyHelper,
    Direction,
} from '@privacyresearch/libsignal-protocol-typescript';
import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts';
import type {
    StorageType,
    KeyPairType,
    SignedPreKeyPairType,
    PreKeyType,
    SignedPublicPreKeyType,
} from '@privacyresearch/libsignal-protocol-typescript';
import KeyStorageService from './KeyStorageService';
import CryptoService from './CryptoService';
import Logger from './Logger';
import { BASE_API_URL } from '../config/Config';
import { AUTHORIZATION_PREFIX } from '../redux/Constants';

/** Maximum number of skipped (out-of-order) message keys to buffer — Signal default */
const MAX_SKIP = 100;

/** Storage key for signed pre-key rotation metadata */
const SIGNED_PREKEY_STORAGE_KEY = 'chatapp_signed_prekey_meta';

/**
 * Signed pre-key metadata stored in localStorage for rotation tracking.
 * Signed pre-keys should be rotated periodically (every 7 days) to limit
 * the damage if one leaks. Signal's spec rotates them weekly.
 */
interface SignedPreKeyMeta {
    currentId: number;
    nextRotationAt: string; // ISO date string
}

export class IdentityChangedError extends Error {
    constructor(public theirUserId: string) {
        super(`Identity key for ${theirUserId} has changed`);
        this.name = 'IdentityChangedError';
    }
}

export interface PreKeyBundleDTO {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    signedPreKeyId: number;
    oneTimePreKeys: string; // JSON array of {id, key} objects
}

export interface RatchetEncryptResult {
    ciphertext: string;
    iv: string;
    ratchetHeader: string; // JSON-encoded header for the recipient to decrypt
}

export interface RatchetDecryptResult {
    plaintext: string;
}

/**
 * In-memory cache for the Signal Protocol store.
 * The library's store interface expects synchronous operations,
 * so we cache sessions in memory and flush to IndexedDB asynchronously.
 *
 * Implements the StorageType interface from the library's types.
 */
class InMemorySignalStore implements StorageType {
    private _sessions: Map<string, string> = new Map();
    private _identityKey: { pubKey: ArrayBuffer; privKey: ArrayBuffer } | undefined;
    private _preKeys: Map<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }> = new Map();
    private _signedPreKey: { pubKey: ArrayBuffer; privKey: ArrayBuffer; signature: ArrayBuffer } | undefined;
    private _registrationId: number = 1;
// Map of remote identity public keys (base64) per contact identifier.
    // Used to PIN identities and reject silently-changed keys (replaces pure TOFU).
    private _knownIdentities: Map<string, string> = new Map();
    // Optional callback to persist a pinned identity to IndexedDB (set by the service).
    // Receives (identifier, base64 identity key).
    private _onIdentityPinned: ((identifier: string, identityKey: string) => Promise<void>) | null = null;
    private _dirtyPreKeyIds: Set<number> = new Set();
    private _removedPreKeyIds: Set<number> = new Set();
    /**
     * Set the persistence callback for pinned identities.
     */
    setOnIdentityPinned(cb: (identifier: string, identityKey: string) => Promise<void>): void {
        this._onIdentityPinned = cb;
    }

    // ── IdentityKeyStore ──

    async getIdentityKeyPair(): Promise<KeyPairType | undefined> {
        return this._identityKey;
    }

    async getLocalRegistrationId(): Promise<number | undefined> {
        return this._registrationId;
    }

    async setIdentityKeyPair(keyPair: KeyPairType): Promise<void> {
        this._identityKey = keyPair;
    }

    async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction: Direction): Promise<boolean> {
        const keyB64 = arrayBufferToBase64(identityKey);
        const known = this._knownIdentities.get(identifier);

        if (!known) {
            // First time we've seen this identity — TOFU on first contact. It is pinned
            // (stored) on the next saveIdentity() call so any later change is rejected.
            return true;
        }

        // We already know this contact's identity — reject if it silently changed.
        // This blocks a malicious server or MITM from substituting identity keys.
        return known === keyB64;
    }

async saveIdentity(_identifier: string, identityKey: ArrayBuffer, _nonblockingApproval?: boolean): Promise<boolean> {
        // Pin the identity key so future changes are rejected in isTrustedIdentity().
        const keyB64 = arrayBufferToBase64(identityKey);
        const existing = this._knownIdentities.get(_identifier);
        if (existing && existing !== keyB64) {
            // Identity changed — do NOT overwrite the pinned key. Return false to reject.
            return false;
        }
        this._knownIdentities.set(_identifier, keyB64);
        // Persist the pin to IndexedDB so it survives reloads (fire-and-forget).
        if (this._onIdentityPinned) {
            this._onIdentityPinned(_identifier, keyB64).catch(() => {});
        }
        return true;
    }

    // ── Custom helpers for identity pinning ──

    getKnownIdentities(): Map<string, string> {
        return new Map(this._knownIdentities);
    }

    setKnownIdentities(identities: Map<string, string>): void {
        this._knownIdentities = new Map(identities);
    }

    // ── Custom helper: explicit user-approved identity override ──
    async forceUpdateIdentity(identifier: string, identityKey: ArrayBuffer): Promise<void> {
        const keyB64 = arrayBufferToBase64(identityKey);
        this._knownIdentities.set(identifier, keyB64);
        if (this._onIdentityPinned) {
            await this._onIdentityPinned(identifier, keyB64).catch(() => {});
        }
    }

    // ── PreKeyStore ──

    async loadPreKey(keyId: number | string): Promise<KeyPairType | undefined> {
        const kid = typeof keyId === 'string' ? parseInt(keyId, 10) : keyId;
        const key = this._preKeys.get(kid);
        if (!key) return undefined;
        return {
            pubKey: key.pubKey,
            privKey: key.privKey,
        };
    }

    async storePreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
        const kid = typeof keyId === 'string' ? parseInt(keyId, 10) : keyId;
        this._preKeys.set(kid, keyPair);
        this._dirtyPreKeyIds.add(kid);
    }

    async removePreKey(keyId: number | string): Promise<void> {
        const kid = typeof keyId === 'string' ? parseInt(keyId, 10) : keyId;
        this._preKeys.delete(kid);
        this._dirtyPreKeyIds.delete(kid);
        this._removedPreKeyIds.add(kid);
    }

    // ── SignedPreKeyStore ──

    async loadSignedPreKey(_keyId: number | string): Promise<KeyPairType | undefined> {
        if (!this._signedPreKey) return undefined;
        return {
            pubKey: this._signedPreKey.pubKey,
            privKey: this._signedPreKey.privKey,
        };
    }

    async storeSignedPreKey(_keyId: number | string, keyPair: KeyPairType): Promise<void> {
        // We only maintain one signed pre-key at a time
        this._signedPreKey = { ...keyPair, signature: new ArrayBuffer(0) };
    }

    async removeSignedPreKey(_keyId: number | string): Promise<void> {
        this._signedPreKey = undefined;
    }

    // ── SessionStore ──

    async loadSession(identifier: string): Promise<string | undefined> {
        return this._sessions.get(identifier);
    }

    async storeSession(identifier: string, sessionData: string): Promise<void> {
        this._sessions.set(identifier, sessionData);
    }

    async removeSession(identifier: string): Promise<void> {
        this._sessions.delete(identifier);
    }

    async removeAllSessions(identifier: string): Promise<void> {
        for (const key of Array.from(this._sessions.keys())) {
            if (key.startsWith(identifier)) {
                this._sessions.delete(key);
            }
        }
    }

    async getSubDeviceSessions(identifier: string): Promise<number[]> {
        return [1]; // Single active device per user
    }

    // ── Custom helpers (not part of StorageType) ──

    getSessionMap(): Map<string, string> {
        return new Map(this._sessions);
    }

    setSessionMap(sessions: Map<string, string>): void {
        this._sessions = new Map(sessions);
    }

getPreKeyCount(): number {
        return this._preKeys.size;
    }

    setSignedPreKeyWithSignature(key: { pubKey: ArrayBuffer; privKey: ArrayBuffer; signature: ArrayBuffer }): void {
        this._signedPreKey = key;
    }

    getSignedPreKeySignature(): ArrayBuffer | undefined {
        return this._signedPreKey?.signature ?? undefined;
    }

    // ── Custom accessors for persistence ──

    getPreKeysMap(): Map<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }> {
        return new Map(this._preKeys);
    }

    setPreKeysMap(map: Map<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }>): void {
        this._preKeys = new Map(map);
    }

    getSignedPreKeyRecord(): { pubKey: ArrayBuffer; privKey: ArrayBuffer; signature: ArrayBuffer } | undefined {
        return this._signedPreKey;
    }

    setSignedPreKeyRecord(key: { pubKey: ArrayBuffer; privKey: ArrayBuffer; signature: ArrayBuffer }| undefined): void {
        this._signedPreKey = key;
    }

    setRegistrationId(id: number): void {
        this._registrationId = id;
    }

    getRegistrationId(): number {
        return this._registrationId;
    }

    getDirtyPreKeyIds(): number[] {
        return Array.from(this._dirtyPreKeyIds);
    }

    getRemovedPreKeyIds(): number[] {
        return Array.from(this._removedPreKeyIds);
    }

    clearDirtyTracking(): void {
        this._dirtyPreKeyIds.clear();
        this._removedPreKeyIds.clear();
    }
}

class SessionRatchetService {
    private store: InMemorySignalStore = new InMemorySignalStore();
    private currentUserId: string | null = null;
    private currentDeviceId: string | null = null;
    // Map of in-flight lazy session initializations per (myUserId:theirUserId).
    // This prevents concurrent `processPreKey` calls for the same pair.
    private inFlightSessionInits: Map<string, Promise<void>> = new Map();
    private isLoaded: boolean = false;
    private identityKeyPair: KeyPairType | undefined;
    private storeEncryptionKey: CryptoKey | null = null;
    private localCacheEncryptionKey: CryptoKey | null = null;
    private readonly tempSentMessageTtlMs = 7 * 24 * 60 * 60 * 1000;
    private decryptedMessageCache: Map<string, string> = new Map();
    private initPromise: Promise<void> | null = null;
    private inFlightDecryptions: Map<string, Promise<string>> = new Map();

    /**
     * Initialize the ratchet service for the current user.
     * Must be called after signup / signin, before any ratchet operations.
     *
     * @param userId - The current user's ID (string)
     * @param curve25519PrivateKey - The Curve25519 private key (base64) from IndexedDB
     * @param curve25519PublicKey - The Curve25519 public key (base64) from IndexedDB
     * @param deviceId - The device ID from KeyStorageService
     */
    async initialize(
        userId: string,
        curve25519PrivateKey: string,
        curve25519PublicKey: string,
        deviceId: string
    ): Promise<void> {
        if (this.currentUserId === userId && this.isLoaded && this.identityKeyPair) {
            const cachedPubKeyB64 = arrayBufferToBase64(this.identityKeyPair.pubKey);
            if (cachedPubKeyB64 === curve25519PublicKey) {
                console.log(`[RATCHET] initialize: already initialized for userId=${userId} with same identity`);
                return;
            }
            console.log(`[RATCHET] initialize: identity CHANGED for userId=${userId}, forcing re-init`);
        }
        if (this.initPromise) {
            console.log(`[RATCHET] initialize: initialization already in progress, awaiting...`);
            await this.initPromise;
            return;
        }

        this.initPromise = (async () => {
            this.currentUserId = userId;
            this.currentDeviceId = deviceId;
            this.isLoaded = false;
            console.log(`[RATCHET] initialize START userId=${userId} deviceId=${deviceId}`);

            // Derive a store encryption key from the Curve25519 private key material
            // This key is used to encrypt session data at rest in IndexedDB
            const storeKeyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(curve25519PrivateKey.substring(0, 32)),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            this.storeEncryptionKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: new TextEncoder().encode('chatapp-ratchet-store-' + userId),
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                storeKeyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            this.localCacheEncryptionKey = await this._deriveLocalCacheEncryptionKey(userId, curve25519PrivateKey);
            await this._loadOrPersistLocalCacheKey(userId);
            await this._cleanupExpiredTempSentMessages(userId);
            console.log(`[RATCHET] initialize: storeEncryptionKey derived for userId=${userId}`);

            // Rebuild the identity key pair from the stored Curve25519 keys
            // KeyHelper.importIdentityKeyPair() does not exist in the actual library API,
            // so we construct the KeyPairType<ArrayBuffer> manually from base64 strings.
            const identityKeyPair: KeyPairType = {
                pubKey: base64ToArrayBuffer(curve25519PublicKey),
                privKey: base64ToArrayBuffer(curve25519PrivateKey),
            };
            this.identityKeyPair = identityKeyPair;
            await this.store.setIdentityKeyPair(identityKeyPair);
            console.log(`[RATCHET] initialize: identity pubKeyHash=${await hashForLog(curve25519PublicKey)} privKeyLen=${curve25519PrivateKey.length}`);

            // Wire identity pin persistence to IndexedDB so pinned contact keys survive reloads.
            this.store.setOnIdentityPinned(async (identifier, identityKey) => {
                await KeyStorageService.saveIdentity({
                    identifier,
                    identityKey,
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                });
            });

            // Load persisted sessions from IndexedDB
            await this._loadSessionsFromStorage();

            // Load persisted one-time pre-keys, signed pre-key, and registration ID
            // so the device can decrypt incoming PreKeyWhisperMessages (type 3) after reload.
            await this._loadRatchetKeysFromStorage();

            // Load persisted pinned identities from IndexedDB (survives reloads).
            try {
                const storedIdentities = await KeyStorageService.getAllIdentities();
                const identityMap = new Map<string, string>();
                for (const rec of storedIdentities) {
                    identityMap.set(rec.identifier, rec.identityKey);
                }
                this.store.setKnownIdentities(identityMap);
            } catch (error) {
                Logger.warn('Failed to load pinned identities:', error);
            }

            this.isLoaded = true;
            console.log(`[RATCHET] initialize DONE userId=${userId} sessions=${this.store.getSessionMap().size} preKeys=${this.store.getPreKeyCount()} signedPreKey=${!!this.store.getSignedPreKeyRecord()}`);
            Logger.cryptoEvent('SessionRatchetService.initialize', { userId, deviceId });
        })();

        try {
            await this.initPromise;
        } finally {
            this.initPromise = null;
        }
    }

    private async _deriveLocalCacheEncryptionKey(userId: string, curve25519PrivateKey: string): Promise<CryptoKey> {
        const storeKeyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(curve25519PrivateKey.substring(0, 32)),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new TextEncoder().encode('chatapp-own-message-cache-' + userId),
                iterations: 100000,
                hash: 'SHA-256',
            },
            storeKeyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    private async _loadOrPersistLocalCacheKey(userId: string): Promise<void> {
        if (!this.storeEncryptionKey) {
            return;
        }

        // Always use the derived key directly to ensure it survives logout/login consistently.
        // We still write it to IndexedDB so the record exists, but we don't overwrite our in-memory key with it.
        try {
            const storedKey = await KeyStorageService.getLocalCacheKey(userId);
            if (!storedKey) {
                const wrapped = await this._encryptLocalCacheKeyMaterial(this.localCacheEncryptionKey!);
                await KeyStorageService.saveLocalCacheKey({
                    userId,
                    encryptedKey: wrapped.encryptedKey,
                    iv: wrapped.iv,
                    createdAt: new Date().toISOString(),
                });
            }
        } catch (error) {
            Logger.warn('Failed to persist local cache key:', error);
        }
    }

    private async _cleanupExpiredTempSentMessages(userId: string): Promise<void> {
        try {
            await KeyStorageService.deleteExpiredTempSentMessages(userId, this.tempSentMessageTtlMs);
        } catch (error) {
            Logger.warn('Failed to clean up expired temp sent-message cache entries:', error);
        }
    }

    private async _encryptLocalCacheKeyMaterial(key: CryptoKey): Promise<{ encryptedKey: string; iv: string }> {
        if (!this.storeEncryptionKey) {
            throw new Error('Store encryption key not available');
        }
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const rawBytes = await crypto.subtle.exportKey('raw', key);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.storeEncryptionKey,
            rawBytes
        );
        return {
            encryptedKey: arrayBufferToBase64(ciphertext),
            iv: arrayBufferToBase64(iv.buffer),
        };
    }

    private async _decryptLocalCacheKeyMaterial(encryptedKey: string, iv: string): Promise<CryptoKey> {
        if (!this.storeEncryptionKey) {
            throw new Error('Store encryption key not available');
        }
        const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBytes },
            this.storeEncryptionKey,
            base64ToArrayBuffer(encryptedKey)
        );
        return crypto.subtle.importKey('raw', decrypted, 'AES-GCM', false, ['encrypt', 'decrypt']);
    }

    /**
     * Get the current signed pre-key ID and decide if rotation is needed.
     * Signed pre-keys are rotated every 7 days to limit the damage if one leaks.
     */
    private _getOrCreateSignedPreKeyMeta(): SignedPreKeyMeta {
        const stored = localStorage.getItem(SIGNED_PREKEY_STORAGE_KEY);
        if (stored) {
            try {
                const meta: SignedPreKeyMeta = JSON.parse(stored);
                // Check if rotation is needed (past the expiration date)
                if (new Date(meta.nextRotationAt) > new Date()) {
                    return meta;
                }
                // Rotation needed — fall through to generate new meta
            } catch {
                // Corrupted — generate fresh
            }
        }
        // Create fresh meta starting at ID 1
        const meta: SignedPreKeyMeta = {
            currentId: 1,
            nextRotationAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
        };
        localStorage.setItem(SIGNED_PREKEY_STORAGE_KEY, JSON.stringify(meta));
        return meta;
    }

    /**
     * Rotate the signed pre-key to a new ID and update rotation metadata.
     * Called when the current signed pre-key has expired (7-day rotation window).
     */
    private _rotateSignedPreKeyMeta(): SignedPreKeyMeta {
        const meta = this._getOrCreateSignedPreKeyMeta();
        meta.currentId = meta.currentId + 1;
        meta.nextRotationAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        localStorage.setItem(SIGNED_PREKEY_STORAGE_KEY, JSON.stringify(meta));
        return meta;
    }

    /**
     * Generate a fresh pre-key bundle for X3DH session initiation.
     * Called on signup and whenever one-time pre-keys run low.
     * Signed pre-keys rotate IDs periodically (every 7 days) as per Signal spec.
     *
     * @param count - Number of one-time pre-keys to generate (default: 100)
     * @returns The bundle ready for upload to server
     */
    async generatePreKeyBundle(count: number = 100): Promise<PreKeyBundleDTO> {
        if (!this.identityKeyPair) {
            throw new Error('Identity key pair not loaded — call initialize() first');
        }

        // Check if signed pre-key rotation is needed
        const meta = this._getOrCreateSignedPreKeyMeta();
        const rotationNeeded = new Date(meta.nextRotationAt) <= new Date();
        const signedPreKeyId = rotationNeeded
            ? this._rotateSignedPreKeyMeta().currentId
            : meta.currentId;

        // Generate signed pre-key with the current (or rotated) ID
        const signedPreKey = await KeyHelper.generateSignedPreKey(this.identityKeyPair, signedPreKeyId);
        await this.store.storeSignedPreKey(signedPreKey.keyId, {
            pubKey: signedPreKey.keyPair.pubKey,
            privKey: signedPreKey.keyPair.privKey,
        });

        // Store the signature
        this.store.setSignedPreKeyWithSignature({
            pubKey: signedPreKey.keyPair.pubKey,
            privKey: signedPreKey.keyPair.privKey,
            signature: signedPreKey.signature,
        });

        // Generate one-time pre-keys
        const oneTimePreKeys = [];
        for (let i = 0; i < count; i++) {
            const otpk = await KeyHelper.generatePreKey(i + 1);
            await this.store.storePreKey(otpk.keyId, {
                pubKey: otpk.keyPair.pubKey,
                privKey: otpk.keyPair.privKey,
            });
            oneTimePreKeys.push({
                id: otpk.keyId,
                key: arrayBufferToBase64(otpk.keyPair.pubKey),
            });
        }

const identityPubKey = await this.store.getIdentityKeyPair();
        if (!identityPubKey) throw new Error('Identity key not available');

        // Persist the generated one-time pre-keys and signed pre-key so the device
        // can decrypt incoming PreKeyWhisperMessages (type 3) after a reload.
        await this._flushRatchetKeysToStorage();

        Logger.cryptoEvent('SessionRatchetService.generatePreKeyBundle', {
            signedPreKeyId,
            rotationNeeded: String(rotationNeeded),
            oneTimePreKeyCount: count,
        });

        return {
            identityKey: arrayBufferToBase64(identityPubKey.pubKey),
            signedPreKey: arrayBufferToBase64(signedPreKey.keyPair.pubKey),
            signedPreKeySignature: arrayBufferToBase64(signedPreKey.signature),
            signedPreKeyId: signedPreKey.keyId,
            oneTimePreKeys: JSON.stringify(oneTimePreKeys),
        };
    }

    /**
     * Initiate an X3DH session with a recipient using their pre-key bundle.
     * If no one-time pre-key is available, falls back to signed pre-key only.
     *
     * @param theirUserId - The recipient's user ID
     * @param theirBundle - The recipient's pre-key bundle (fetched from server)
     * @param consumeOtpkResult - Optional result from consuming a one-time pre-key
     */
    async initSession(
        theirUserId: string,
        theirBundle: PreKeyBundleDTO,
        consumeOtpkResult?: { id: number; key: string }
    ): Promise<void> {
        if (!this.currentUserId) throw new Error('SessionRatchetService not initialized');

        const theirAddress = new SignalProtocolAddress(theirUserId, 1);
        const persistedSession = await this.store.loadSession(theirAddress.toString());
        if (persistedSession) {
            console.log(`[RATCHET] initSession: reusing persisted session for user=${theirUserId}`);
            Logger.cryptoEvent('SessionRatchetService.initSession.reuse', {
                theirUserId,
            });
            return;
        }

        const sessionBuilder = new SessionBuilder(this.store, theirAddress);

        // Parse one-time pre-keys from bundle
        let otpk: { id: number; key: string } | null = null;
        try {
            const otpks: { id: number; key: string }[] = JSON.parse(theirBundle.oneTimePreKeys);
            if (otpks.length > 0) {
                otpk = otpks[otpks.length - 1];
            }
        } catch {
            // No parseable one-time pre-keys
        }

        // Use the consumed one-time pre-key if available
        if (consumeOtpkResult) {
            otpk = consumeOtpkResult;
        }

        // Process the pre-key bundle to establish the session
        const preKeyBundle = {
            identityKey: base64ToArrayBuffer(theirBundle.identityKey),
            registrationId: 1,
            preKey: otpk ? {
                keyId: otpk.id,
                publicKey: base64ToArrayBuffer(otpk.key),
            } : undefined,
            signedPreKey: {
                keyId: theirBundle.signedPreKeyId,
                publicKey: base64ToArrayBuffer(theirBundle.signedPreKey),
                signature: base64ToArrayBuffer(theirBundle.signedPreKeySignature),
            },
        };

        try {
            await sessionBuilder.processPreKey(preKeyBundle);
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            Logger.error('SessionRatchetService.initSession failed', error);
            if (msg.toLowerCase().includes('identity')) {
                throw new IdentityChangedError(theirUserId);
            }
            throw new Error('Failed to establish X3DH session: ' + msg);
        }

// Persist session to IndexedDB (and ratchet keys so the device can decrypt
        // incoming PreKeyWhisperMessages after a reload).
        await this._flushSessionsToStorage();
        await this._flushRatchetKeysToStorage();
        Logger.cryptoEvent('SessionRatchetService.initSession', {
            theirUserId,
            usedOtpk: String(!!otpk),
        });
    }

    /**
     * Encrypt a plaintext message using the Double Ratchet.
     * Creates a fresh session if one doesn't exist (by fetching their pre-keys).
     *
     * @param plaintext - The message to encrypt
     * @param theirUserId - The recipient's user ID
     * @param authToken - JWT for API calls (for lazy session init)
     * @returns The encrypted result with ratchet header
     */
    async ratchetEncrypt(
        plaintext: string,
        theirUserId: string,
        authToken: string
    ): Promise<RatchetEncryptResult> {
        if (!this.currentUserId || !this.isLoaded) {
            throw new Error('SessionRatchetService not initialized');
        }

        if (theirUserId === this.currentUserId) {
            throw new Error('Self-ratchet encryption is not supported; sender messages use the local cache instead.');
        }

        const theirAddress = new SignalProtocolAddress(theirUserId, 1);

        // Check if session exists, if not — lazy init
        const existingSession = await this.store.loadSession(theirAddress.toString());
        console.log(`[RATCHET] ratchetEncrypt START recipient=${theirUserId} isSelf=${theirUserId === this.currentUserId} sessionExists=${!!existingSession}`);
        Logger.cryptoEvent('ratchetEncrypt.start', {
            myUserId: this.currentUserId,
            recipientId: theirUserId,
            sessionExists: String(!!existingSession),
            plaintextBytes: new TextEncoder().encode(plaintext).byteLength,
        });
        if (!existingSession) {
            await this._lazyInitSession(theirUserId, authToken);
            console.log(`[RATCHET] ratchetEncrypt: session CREATED lazily for recipient=${theirUserId}`);
        }

        // Encrypt using the session cipher
        const cipher = new SessionCipher(this.store, theirAddress);
        const ciphertext = new TextEncoder().encode(plaintext);
        let encrypted;
        try {
            encrypted = await cipher.encrypt(ciphertext.buffer);
        } catch (error) {
            // Flush session state even on error to keep store in sync
            await this._flushSessionsToStorage();
            await this._flushRatchetKeysToStorage();
            Logger.error('ratchetEncrypt.encrypt.threw', {
                recipientId: theirUserId,
                message: (error as Error).message,
            });
            throw error;
        }
        Logger.cryptoEvent('ratchetEncrypt.encrypted', {
            recipientId: theirUserId,
            isSelf: String(theirUserId === this.currentUserId),
            messageType: encrypted.type,
            bodyBytes: (encrypted.body || '').length,
        });

        const iv = crypto.getRandomValues(new Uint8Array(12));

        // The Signal library returns encrypted.body as a RAW BINARY string
        // (each char is a byte 0-255, and it may contain literal \u0000 null bytes).
        // PostgreSQL forbids 0x00 in TEXT/VARCHAR columns, and JSON payloads cannot
        // safely carry raw binary either. So we must base64-encode the binary body
        // before it is stored/sent as content. The decrypt path already expects
        // base64 (base64ToArrayBuffer(header.body)), so this makes the round-trip
        // consistent AND keeps all stored ciphertext a valid UTF-8 base64 string.
        const bodyB64 = arrayBufferToBase64(binaryStringToArrayBuffer(encrypted.body || ''));

        // Build the ratchet header that the recipient needs to decrypt.
        // body is stored as base64 (matching the decrypt path).
        const bodyStr = bodyB64;
        const ratchetHeader = JSON.stringify({
            type: encrypted.type, // 3 = PreKeyWhisperMessage, 1 = WhisperMessage
            body: bodyB64,
            registrationId: encrypted.registrationId,
            deviceId: this.currentDeviceId,
        });

        // Flush session state to IndexedDB after encryption
        await this._flushSessionsToStorage();
        await this._flushRatchetKeysToStorage();

        return {
            ciphertext: bodyStr,
            iv: arrayBufferToBase64(iv.buffer),
            ratchetHeader,
        };
    }

    async clearAllPersistedSessionsForIdentityRegen(): Promise<void> {
        this.store.setSessionMap(new Map());
        this.decryptedMessageCache.clear();
        this.inFlightDecryptions.clear();
        try {
            await KeyStorageService.clearAllSessions();
        } catch (error) {
            Logger.warn('Failed to clear persisted sessions during identity regen:', error);
        }
        if (this.currentUserId) {
            try {
                await KeyStorageService.clearAllSentMessages(this.currentUserId);
            } catch (error) {
                Logger.warn('Failed to clear own sent-message cache during identity regen:', error);
            }
        }
    }

    /**
     * Decrypt a message using the Double Ratchet.
     * Detects the message type (PreKeyWhisperMessage vs WhisperMessage) from the header.
     *
     * @param ratchetHeader - The JSON-encoded ratchet header from the message
     * @param ciphertext - The encrypted message body (base64)
     * @param theirUserId - The sender's user ID
     * @returns The decrypted plaintext
     */
    async ratchetDecrypt(
        ratchetHeader: string,
        ciphertext: string,
        theirUserId: string,
        messageId?: string 
    ): Promise<string> {
        if (!this.currentUserId || !this.isLoaded) {
            throw new Error('SessionRatchetService not initialized');
        }

        if (theirUserId === this.currentUserId) {
            console.log(`[RATCHET] ratchetDecrypt: own message detected, falling back to local cache`);
            if (messageId) {
                const cached = await this.getCachedOwnMessage(messageId);
                if (cached) return cached;
            }
            throw new Error('Self-ratchet decryption is not supported and own-message cache was empty');
        }

        const cacheKey = messageId || `${theirUserId}:${ciphertext}`;

        if (messageId && this.decryptedMessageCache.has(messageId)) {
            console.log(`[RATCHET] ratchetDecrypt: cache hit for messageId=${messageId}`);
            return this.decryptedMessageCache.get(messageId)!;
        }

        const existingPromise = this.inFlightDecryptions.get(cacheKey);
        if (existingPromise) {
            console.log(`[RATCHET] ratchetDecrypt: reuse in-flight decryption for key=${cacheKey}`);
            return existingPromise;
        }

        const decryptPromise = (async () => {
            const theirAddress = new SignalProtocolAddress(theirUserId, 1);
            let parsed;
            try {
                parsed = JSON.parse(ratchetHeader);
            } catch (e) {
                Logger.error('ratchetDecrypt.parseHeader.threw', {
                    theirUserId,
                    headerSlice: ratchetHeader.slice(0, 80),
                    message: (e as Error).message,
                });
                throw new Error('Decryption failed: malformed ratchet header');
            }
            const header = this._selectRatchetHeader(parsed, theirUserId, ciphertext);
            // Resolve the ACTUAL ciphertext to decrypt. When the stored message `content`
            // is the sender's own ciphertext (which happens on a history refetch — the DB
            // stores only the sender's copy), the per-recipient header map still contains
            // THIS user's ciphertext as its `body`. Fall back to that so a receiver can
            // decrypt history reliably, not just live WebSocket messages.
            const effectiveCiphertext = this._resolveCiphertextForCurrentUser(parsed, header, theirUserId, ciphertext);
            const sessionExists = await this.store.loadSession(theirAddress.toString());
            const bodyMatchesContent = header?.body === effectiveCiphertext;
            // Known identity (pinned) for the sender, if any.
            const knownIdentity = this.store.getKnownIdentities().get(theirUserId + '.1');
            
            console.log(`[RATCHET] ratchetDecrypt START sender=${theirUserId} isSelf=${theirUserId === this.currentUserId} myUserId=${this.currentUserId} sessionExists=${!!sessionExists} headerIsMap=${isPerRecipientMap(parsed)} headerType=${header?.type} headerBodyLen=${header?.body?.length ?? 0} bodyMatchesContent=${bodyMatchesContent} contentLen=${(ciphertext || '').length} registrationId=${header?.registrationId ?? 'unknown'} knownSenderIdentity=${knownIdentity ? await hashForLog(knownIdentity) : 'none'}`);
            Logger.cryptoEvent('ratchetDecrypt.start', {
                myUserId: this.currentUserId ?? 'unknown',
                senderId: theirUserId,
                isSelf: String(theirUserId === this.currentUserId),
                sessionExists: String(!!sessionExists),
                headerIsMap: String(isPerRecipientMap(parsed)),
                headerType: header?.type,
                headerBodyLen: header?.body?.length ?? 0,
                bodyMatchesContent: String(bodyMatchesContent),
                registrationId: String(header?.registrationId ?? 'unknown'),
                preKeys: this.store.getPreKeyCount(),
                signedPreKey: String(!!this.store.getSignedPreKeyRecord()),
            });
            const cipher = new SessionCipher(this.store, theirAddress);

            const bodyBuffer = base64ToArrayBuffer(effectiveCiphertext);
            let decrypted: ArrayBuffer;

            try {
                if (header.type === 3) {
                    // PreKeyWhisperMessage — first message in a session
                    console.log(`[RATCHET] decryptPreKeyWhisperMessage (type 3) sender=${theirUserId}`);
                    Logger.cryptoEvent('ratchetDecrypt.type', { messageType: 3, label: 'PreKeyWhisperMessage' });
                    const preKeyMsg = await cipher.decryptPreKeyWhisperMessage(bodyBuffer, 'binary');
                    decrypted = preKeyMsg;
                } else {
                    // Normal WhisperMessage — subsequent messages in an established session
                    console.log(`[RATCHET] decryptWhisperMessage (type ${header?.type}) sender=${theirUserId}`);
                    Logger.cryptoEvent('ratchetDecrypt.type', { messageType: header?.type || 1, label: 'WhisperMessage' });
                    const msg = await cipher.decryptWhisperMessage(bodyBuffer, 'binary');
                    decrypted = msg;
                }

                // Flush session state to IndexedDB after decryption
                await this._flushSessionsToStorage();
                await this._flushRatchetKeysToStorage();

                const plaintext = new TextDecoder().decode(decrypted);
                if (messageId) {
                    this.decryptedMessageCache.set(messageId, plaintext);  
                }
                console.log(`[RATCHET] ratchetDecrypt SUCCESS sender=${theirUserId} isSelf=${theirUserId === this.currentUserId} plaintextBytes=${plaintext.length}`);
                Logger.cryptoEvent('ratchetDecrypt.success', {
                    theirUserId,
                    isSelf: String(theirUserId === this.currentUserId),
                    plaintextBytes: plaintext.length,
                });
                return plaintext;
            } catch (error) {
                // Ensure state is flushed even on failure to prevent divergence
                await this._flushSessionsToStorage();
                await this._flushRatchetKeysToStorage();

                console.error('[RATCHET] ratchetDecrypt FAILED', {
                    theirUserId,
                    isSelf: theirUserId === this.currentUserId,
                    myUserId: this.currentUserId,
                    headerType: header?.type,
                    bodyLen: (header.body || '').length,
                    sessionExists: !!sessionExists,
                    registrationId: header?.registrationId ?? 'unknown',
                    preKeys: this.store.getPreKeyCount(),
                    signedPreKey: !!this.store.getSignedPreKeyRecord(),
                    error,
                });
                Logger.error('SessionRatchetService.ratchetDecrypt failed', {
                    theirUserId,
                    isSelf: String(theirUserId === this.currentUserId),
                    headerType: header?.type,
                    bodyLen: (header.body || '').length,
                    sessionExists: String(!!sessionExists),
                    registrationId: String(header?.registrationId ?? 'unknown'),
                    preKeys: this.store.getPreKeyCount(),
                    signedPreKey: String(!!this.store.getSignedPreKeyRecord()),
                    error: error instanceof Error ? error.message : String(error),
                });

                // If decryption fails, the session may have been invalidated
                // (e.g., user registered on a new device, replacing their pre-key bundle)
                                const errorMessage = error instanceof Error ? error.message : String(error);
                if (
                    errorMessage?.toLowerCase().includes('identity') ||
                    (knownIdentity && header?.type === 3)
                ) {
                    console.warn(`[RATCHET] ratchetDecrypt: treating as identity change for sender=${theirUserId} (pinnedIdentityExists=${!!knownIdentity}, headerType=${header?.type}, rawError=${errorMessage})`);
                    throw new IdentityChangedError(theirUserId);
                }
                if (errorMessage?.includes('session')) {
                    console.warn(`[RATCHET] ratchetDecrypt: dropping session for sender=${theirUserId} due to session error`);
                    await this.store.removeSession(theirAddress.toString());
                    await this._flushSessionsToStorage();
                }

                throw error;
            }
        })();

        this.inFlightDecryptions.set(cacheKey, decryptPromise);

        try {
            return await decryptPromise;
        } finally {
            this.inFlightDecryptions.delete(cacheKey);
        }
    }

/**
     * Select the header for the current user when the message stores per-recipient headers.
     *
     * The stored message content is the ciphertext encrypted FOR THE SENDER (so the
     * sender can decrypt their own history). Other recipients receive their own
     * ciphertext via WebSocket. To make selection robust, we prefer the header whose
     * {@code body} exactly matches the provided ciphertext — this guarantees the
     * correct header is paired with the correct ciphertext regardless of which user
     * is decrypting.
     */
private _selectRatchetHeader(parsedHeader: any, theirUserId: string, content?: string): { type: number; body: string; registrationId?: number; deviceId?: string } {
        // Fast path: a single header (has 'body' directly), not a per-recipient map.
        if (!isPerRecipientMap(parsedHeader)) {
            return parsedHeader;
        }

        const keys = Object.keys(parsedHeader);

        // 1. Prefer a header whose body matches the ciphertext we are trying to decrypt.
        if (content) {
            for (const value of Object.values(parsedHeader)) {
                let candidate: any = value;
                if (typeof value === 'string') {
                    try { candidate = JSON.parse(value); } catch { continue; }
                }
                if (candidate && typeof candidate === 'object' && candidate.body === content) {
                    console.log(`[RATCHET] _selectRatchetHeader: chose body-match header (contentLen=${(content || '').length})`);
                    return candidate;
                }
            }
        }

        const currentUserHeader = this.currentUserId ? parsedHeader[this.currentUserId] : undefined;
        const senderHeader = parsedHeader[theirUserId];
        const selected = currentUserHeader ?? senderHeader ?? Object.values(parsedHeader)[0];

        let result: any = selected;
        if (typeof selected === 'string') {
            try { result = JSON.parse(selected); } catch { result = null; }
        }
console.log(`[RATCHET] _selectRatchetHeader: no body-match; headerKeys=${keys.join(',')} currentUserId=${this.currentUserId} senderId=${theirUserId} selectedKey=${keys.find(k => parsedHeader[k] === selected)} resultType=${result?.type}`);
        return result;
    }

    /**
     * Resolve the ACTUAL ciphertext to decrypt for the current user.
     *
     * The DB stores only the SENDER's ciphertext in the message `content` field.
     * On a live WebSocket delivery, the recipient gets their own per-recipient
     * ciphertext via the WS payload (so `content` matches their header body).
     * BUT on a history refetch (reload / reopen chat), `content` is the sender's
     * ciphertext, which does NOT match this user's header. In that case the
     * per-recipient header map still contains THIS user's ciphertext as its
     * `body` — so we fall back to the header's body for the current user.
     *
     * Priority:
     *   1. The stored `content` if it equals the selected header's body (live WS case).
     *   2. The current user's header body (history refetch case).
     *   3. The sender's header body (group fallback).
     *   4. The selected header's body (last resort).
     */
    private _resolveCiphertextForCurrentUser(
        parsedHeader: any,
        selectedHeader: { type: number; body: string; registrationId?: number; deviceId?: string } | null,
        theirUserId: string,
        content?: string
    ): string {
        // Single-header fast path: content is authoritative.
        if (!isPerRecipientMap(parsedHeader)) {
            return content || (selectedHeader?.body || '');
        }

        // 1. Live WebSocket case — content already matches the selected header's body.
        if (content && selectedHeader && selectedHeader.body === content) {
            return content;
        }

        // 2. History refetch case — pull THIS user's ciphertext from the header map.
        if (this.currentUserId && parsedHeader[this.currentUserId]) {
            let mine: any = parsedHeader[this.currentUserId];
            if (typeof mine === 'string') { try { mine = JSON.parse(mine); } catch { mine = null; } }
            if (mine && typeof mine === 'object' && mine.body) {
                return mine.body;
            }
        }

        // 3. Sender's own header (group fallback).
        if (parsedHeader[theirUserId]) {
            let senders: any = parsedHeader[theirUserId];
            if (typeof senders === 'string') { try { senders = JSON.parse(senders); } catch { senders = null; } }
            if (senders && typeof senders === 'object' && senders.body) {
                return senders.body;
            }
        }

        // 4. Last resort — the selected header's body.
        return selectedHeader?.body || content || '';
    }

    /**
     * Check if a session exists with the given user.
     */
    async hasSession(theirUserId: string): Promise<boolean> {
        if (!this.currentUserId) return false;
        const theirAddress = new SignalProtocolAddress(theirUserId, 1);
        const session = await this.store.loadSession(theirAddress.toString());
        return !!session;
    }

    /**
     * Clear all session data (on logout).
     */
    async clearAllSessions(): Promise<void> {
        this.store.setSessionMap(new Map());
        this.store.setPreKeysMap(new Map());
        this.store.setSignedPreKeyRecord(undefined);
        this.store.setRegistrationId(1);
        this.store.setKnownIdentities(new Map());
        this.isLoaded = false;
        this.currentUserId = null;
        this.currentDeviceId = null;
        this.identityKeyPair = undefined;
        this.storeEncryptionKey = null;
        this.localCacheEncryptionKey = null;
        this.decryptedMessageCache.clear();
        this.inFlightSessionInits.clear();
        this.inFlightDecryptions.clear();
        Logger.cryptoEvent('SessionRatchetService.clearAllSessions', {});
    }

    /**
     * Cache the sender's own plaintext locally for instant rendering after send.
     * This is intentionally per-device by design, matching Signal's pre-linked-device
     * behavior: a second device or cleared local storage will not have the sender's
     * own historical plaintext until multi-device sync is implemented.
     */
    // Per-device own-message cache avoids unsupported Double Ratchet self-session decrypts while keeping plaintext off the server.
    async cacheOwnSentMessage(messageId: string, plaintext: string): Promise<void> {
        if (!this.currentUserId || !this.isLoaded || !this.localCacheEncryptionKey) {
            return;
        }
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.localCacheEncryptionKey,
            new TextEncoder().encode(plaintext)
        );
        await KeyStorageService.saveSentMessage({
            messageId,
            userId: this.currentUserId,
            encryptedPlaintext: arrayBufferToBase64(ciphertext),
            iv: arrayBufferToBase64(iv.buffer),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        });
    }

    async getCachedOwnMessage(messageId: string): Promise<string | null> {
        if (!this.currentUserId || !this.isLoaded || !this.localCacheEncryptionKey) {
            return null;
        }
        const record = await KeyStorageService.getSentMessage(messageId);
        if (!record) {
            return null;
        }
        const iv = new Uint8Array(base64ToArrayBuffer(record.iv));
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.localCacheEncryptionKey,
            base64ToArrayBuffer(record.encryptedPlaintext)
        );
        return new TextDecoder().decode(decrypted);
    }

    async deleteCachedOwnMessage(messageId: string): Promise<void> {
        await KeyStorageService.deleteSentMessage(messageId);
    }

    async rekeyCachedOwnMessage(oldMessageId: string, newMessageId: string): Promise<boolean> {
        return KeyStorageService.rekeySentMessage(oldMessageId, newMessageId);
    }

/**
     * Compute a safety number (60-bit fingerprint) from the two users' identity
     * public keys. This is shown to both users so they can verify the session
     * out-of-band (e.g., comparing a short numeric/word code).
     *
     * @param theirUserId - The contact's user ID
     * @param theirIdentityKey - The contact's identity public key (base64)
     * @returns A 6-group numeric safety number (e.g., "12345 67890 ...")
     */
    async getSafetyNumber(theirUserId: string, theirIdentityKey: string): Promise<string> {
        if (!this.identityKeyPair) {
            throw new Error('Identity key pair not loaded — call initialize() first');
        }
        const myPub = arrayBufferToBase64(this.identityKeyPair.pubKey);
        const combined = `${myPub}${theirIdentityKey}`;
        const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(combined));
        const hashBytes = new Uint8Array(hashBuf);
        // Take the first 6 bytes (48 bits) and split into 6 groups of 5 digits each.
        const groups: string[] = [];
        for (let i = 0; i < 6; i++) {
            const val = (hashBytes[i * 6] * 256 + hashBytes[i * 6 + 1]) % 100000;
            groups.push(String(val).padStart(5, '0'));
        }
        return groups.join(' ');
    }

    /**
     * Explicitly accept a contact's new identity key after the user has been warned.
     * Re-pins the identity, discards the stale session so the next send/receive
     * does fresh X3DH, and persists both changes.
     */
    async acceptNewIdentityAndReset(theirUserId: string, authToken: string): Promise<void> {
        if (!this.currentUserId) throw new Error('SessionRatchetService not initialized');
        const theirAddress = new SignalProtocolAddress(theirUserId, 1);

        const bundleRes = await fetch(
            `${BASE_API_URL}/api/users/${theirUserId}/pre-key-bundle`,
            { headers: { Authorization: `${AUTHORIZATION_PREFIX}${authToken}` } }
        );
        if (!bundleRes.ok) throw new Error('Failed to fetch updated pre-key bundle for identity refresh');
        const bundle: PreKeyBundleDTO = await bundleRes.json();

        await this.store.forceUpdateIdentity(theirAddress.toString(), base64ToArrayBuffer(bundle.identityKey));
        await this.store.removeSession(theirAddress.toString());
        await this._flushSessionsToStorage();

        Logger.cryptoEvent('SessionRatchetService.acceptNewIdentityAndReset', { theirUserId });
    }

    /**
     * Get the count of remaining one-time pre-keys in the in-memory store.
     * When this drops below a threshold (e.g., 20), the client should
     * generate and upload a fresh batch.
     */
    getOneTimePreKeyCount(): number {
        return this.store.getPreKeyCount();
    }

    /**
     * Lazy-initialize a session by fetching the recipient's pre-key bundle
     * and consuming one of their one-time pre-keys atomically.
     */
private async _lazyInitSession(theirUserId: string, authToken: string): Promise<void> {
        Logger.cryptoEvent('SessionRatchetService._lazyInitSession', {
            myUserId: this.currentUserId ?? 'unknown',
            theirUserId,
            isSelf: String(theirUserId === this.currentUserId),
        });

        if (!this.currentUserId) throw new Error('SessionRatchetService not initialized');

        const key = `${this.currentUserId}:${theirUserId}`;
        const existing = this.inFlightSessionInits.get(key);
        if (existing) {
            Logger.cryptoEvent('SessionRatchetService._lazyInitSession.reuse', {
                myUserId: this.currentUserId,
                theirUserId,
            });
            await existing;
            return;
        }

        const persistedSession = await this.store.loadSession(new SignalProtocolAddress(theirUserId, 1).toString());
        if (persistedSession) {
            console.log(`[RATCHET] _lazyInitSession: reusing persisted session for user=${theirUserId}`);
            Logger.cryptoEvent('SessionRatchetService._lazyInitSession.persistedReuse', {
                myUserId: this.currentUserId,
                theirUserId,
            });
            return;
        }

        console.log(`[RATCHET] _lazyInitSession: establishing new session for user=${theirUserId}`);

        const p = (async () => {
            try {
                // 1. Fetch their pre-key bundle
                const bundleRes = await fetch(
                    `${BASE_API_URL}/api/users/${theirUserId}/pre-key-bundle`,
                    { headers: { Authorization: `${AUTHORIZATION_PREFIX}${authToken}` } }
                );
                Logger.cryptoEvent('_lazyInitSession.fetchBundle', {
                    theirUserId,
                    status: bundleRes.status,
                });
                if (bundleRes.status === 204) {
                    throw new Error(`User ${theirUserId} has no pre-key bundle — they cannot receive ratchet messages yet.`);
                }
                const bundle: PreKeyBundleDTO = await bundleRes.json();
                let otpkCount = 0;
                try { otpkCount = (JSON.parse(bundle.oneTimePreKeys || '[]') as any[]).length; } catch { otpkCount = 0; }
                console.log(`[RATCHET] _lazyInitSession: fetched bundle for user=${theirUserId} identityKeyHash=${await hashForLog(bundle.identityKey || '')} signedPreKeyId=${bundle.signedPreKeyId} otpkCount=${otpkCount} isSelf=${theirUserId === this.currentUserId}`);

                // 2. Atomically consume a one-time pre-key
                const consumeRes = await fetch(
                    `${BASE_API_URL}/api/users/pre-key-bundle/consume`,
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            Authorization: `${AUTHORIZATION_PREFIX}${authToken}`,
                        },
                        body: JSON.stringify({ senderUserId: theirUserId }),
                    }
                );
                Logger.cryptoEvent('_lazyInitSession.consume', {
                    theirUserId,
                    status: consumeRes.status,
                });

                let consumedKey: { id: number; key: string } | undefined;
                if (consumeRes.status === 200) {
                    const consumedStr = await consumeRes.text();
                    consumedKey = JSON.parse(consumedStr);
                }

                // 3. Initialize session from the bundle
                await this.initSession(theirUserId, bundle, consumedKey);
            } finally {
                // Ensure the in-flight entry is cleared regardless of success/failure
                this.inFlightSessionInits.delete(key);
            }
        })();

        this.inFlightSessionInits.set(key, p);
        await p;
    }

/**
     * Load all persisted sessions from IndexedDB into the in-memory store.
     * Sessions are encrypted at rest — decrypt them on load.
     *
     * Iterates all stored sessions from the IndexedDB ratchetSessions store
     * (not the in-memory map, which is empty on initialization).
     */
    private async _loadSessionsFromStorage(): Promise<void> {
        try {
            const allSessions = new Map<string, string>();
            // Load sessions from IndexedDB — iterate known session keys
            // KeyStorageService stores sessions with userId as the keyPath (e.g., "99.1")
            // We load all sessions by iterating the store via getAllKeys
            const db = await this._openKeyStoreDb();
            const tx = db.transaction('ratchetSessions', 'readonly');
            const store = tx.objectStore('ratchetSessions');
            const allKeys: IDBValidKey[] = await new Promise((resolve, reject) => {
                const req = store.getAllKeys();
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
            for (const key of allKeys) {
                const address = key.toString();
                try {
                    const stored = await KeyStorageService.loadSession(address);
                    if (stored && stored.sessionData) {
                        const decrypted = await this._decryptSessionData(stored.sessionData);
                        allSessions.set(address, decrypted);
                    }
                } catch {
                    // Corrupted session data — skip
                    Logger.warn('Failed to decrypt session:', address);
                }
            }
            this.store.setSessionMap(allSessions);
            Logger.cryptoEvent('SessionRatchetService._loadSessions', {
                count: allSessions.size,
            });
        } catch (error) {
            Logger.error('SessionRatchetService._loadSessions failed', error);
        }
    }

    /**
     * Open IndexedDB directly to iterate all session keys.
     */
private async _openKeyStoreDb(): Promise<IDBDatabase> {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('chatapp-keystore', 6);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Encrypt session data for storage in IndexedDB.
     * Uses AES-GCM with the store encryption key derived from the user's Curve25519 private key.
     */
    private async _encryptSessionData(sessionData: string): Promise<string> {
        if (!this.storeEncryptionKey) return sessionData; // fallback

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(sessionData);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.storeEncryptionKey,
            encoded
        );
        // Combine IV + ciphertext for storage
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return arrayBufferToBase64(combined.buffer);
    }

    /**
     * Persist the current session map to IndexedDB via KeyStorageService.
     * Each session is encrypted at rest using the store encryption key.
     */
    private async _flushSessionsToStorage(): Promise<void> {
        if (!this.currentUserId) return;
        const sessionMap = this.store.getSessionMap();
        const deviceId = KeyStorageService.getOrCreateDeviceId();
        for (const [address, sessionData] of Array.from(sessionMap)) {
            try {
                const encrypted = await this._encryptSessionData(sessionData);
                await KeyStorageService.saveSession({
                    userId: address,
                    deviceId,
                    sessionData: encrypted,
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                });
            } catch (error) {
                Logger.warn('Failed to persist session:', address, error);
            }
        }
    }

    /**
     * Decrypt session data loaded from IndexedDB.
     */
    private async _decryptSessionData(encryptedData: string): Promise<string> {
        if (!this.storeEncryptionKey) return encryptedData; // fallback

        const combined = new Uint8Array(base64ToArrayBuffer(encryptedData));
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.storeEncryptionKey,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

/**
     * Load one-time pre-keys, signed pre-key, and registration ID from IndexedDB
     * into the in-memory store. Called during initialize() so the device can
     * decrypt incoming PreKeyWhisperMessages (type 3) after a reload/logout.
     */
private async _loadRatchetKeysFromStorage(): Promise<void> {
        if (!this.currentUserId) return;
        try {
            const userId = this.currentUserId;
            // One-time pre-keys (scoped by userId)
            const storedPreKeys = await KeyStorageService.getAllPreKeys(userId);
            const preKeyMap = new Map<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }>();
            for (const rec of storedPreKeys) {
                try {
                    const pubKey = base64ToArrayBuffer(rec.pubKey);
                    const privKey = base64ToArrayBuffer(await this._decryptKeyMaterial(rec.privKey));
                    preKeyMap.set(rec.id, { pubKey, privKey });
                } catch {
                    Logger.warn('Failed to decrypt pre-key:', rec.id);
                }
            }
            this.store.setPreKeysMap(preKeyMap);
            console.log(`[RATCHET] _loadRatchetKeys: loaded preKeys=${preKeyMap.size} for currentUser=${userId}`);

            // Signed pre-key (scoped by userId)
            const storedSigned = await KeyStorageService.getAllSignedPreKeys(userId);
            if (storedSigned.length > 0) {
                const rec = storedSigned[0];
                try {
                    const pubKey = base64ToArrayBuffer(rec.pubKey);
                    const privKey = base64ToArrayBuffer(await this._decryptKeyMaterial(rec.privKey));
                    const signature = base64ToArrayBuffer(rec.signature);
                    this.store.setSignedPreKeyRecord({ pubKey, privKey, signature });
                    console.log(`[RATCHET] _loadRatchetKeys: loaded signedPreKey id=${rec.id} for currentUser=${userId}`);
                } catch {
                    Logger.warn('Failed to decrypt signed pre-key:', rec.id);
                }
            } else {
                console.log(`[RATCHET] _loadRatchetKeys: NO signed pre-key found for currentUser=${userId}`);
            }

            // Registration ID (scoped by userId)
            const storedReg = await KeyStorageService.loadRegistrationId(userId);
            if (storedReg) {
                this.store.setRegistrationId(storedReg.registrationId);
                console.log(`[RATCHET] _loadRatchetKeys: loaded registrationId=${storedReg.registrationId} for currentUser=${userId}`);
            }

            Logger.cryptoEvent('SessionRatchetService._loadRatchetKeys', {
                preKeys: this.store.getPreKeyCount(),
                signedPreKey: String(!!this.store.getSignedPreKeyRecord()),
                registrationId: this.store.getRegistrationId(),
            });
        } catch (error) {
            Logger.error('SessionRatchetService._loadRatchetKeys failed', error);
        }
    }

    /**
     * Persist one-time pre-keys, signed pre-key, and registration ID to IndexedDB.
     * Private key material is encrypted at rest using the store encryption key.
     */
private async _flushRatchetKeysToStorage(): Promise<void> {
    if (!this.currentUserId) return;
    const userId = this.currentUserId;
    try {
        const dirtyIds = this.store.getDirtyPreKeyIds();
        const removedIds = this.store.getRemovedPreKeyIds();
        const preKeyMap = this.store.getPreKeysMap();

        for (const id of dirtyIds) {
            const kp = preKeyMap.get(id);
            if (!kp) continue;
            try {
                const encryptedPriv = await this._encryptKeyMaterial(arrayBufferToBase64(kp.privKey));
                await KeyStorageService.savePreKey({
                    userId,
                    id,
                    pubKey: arrayBufferToBase64(kp.pubKey),
                    privKey: encryptedPriv,
                    createdAt: new Date().toISOString(),
                });
            } catch (error) {
                Logger.warn('Failed to persist pre-key:', id, error);
            }
        }

        for (const id of removedIds) {
            try {
                await KeyStorageService.deletePreKey(userId, id);
            } catch (error) {
                Logger.warn('Failed to delete consumed pre-key:', id, error);
            }
        }

        this.store.clearDirtyTracking();

        // Signed pre-key + registration ID are single records — cheap, keep as-is
        const signed = this.store.getSignedPreKeyRecord();
        if (signed) {
            try {
                const encryptedPriv = await this._encryptKeyMaterial(arrayBufferToBase64(signed.privKey));
                await KeyStorageService.saveSignedPreKey({
                    userId,
                    id: 1,
                    pubKey: arrayBufferToBase64(signed.pubKey),
                    privKey: encryptedPriv,
                    signature: arrayBufferToBase64(signed.signature),
                    createdAt: new Date().toISOString(),
                });
            } catch (error) {
                Logger.warn('Failed to persist signed pre-key:', error);
            }
        }

        await KeyStorageService.saveRegistrationId({
            userId,
            registrationId: this.store.getRegistrationId(),
            createdAt: new Date().toISOString(),
        });
    } catch (error) {
        Logger.error('SessionRatchetService._flushRatchetKeysToStorage failed', error);
    }
}

    /**
     * Encrypt arbitrary key material (as base64 string) for storage at rest.
     */
    private async _encryptKeyMaterial(base64: string): Promise<string> {
        if (!this.storeEncryptionKey) return base64; // fallback
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(base64);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.storeEncryptionKey,
            encoded
        );
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return arrayBufferToBase64(combined.buffer);
    }

    /**
     * Decrypt key material stored at rest back to a base64 string.
     */
    private async _decryptKeyMaterial(encrypted: string): Promise<string> {
        if (!this.storeEncryptionKey) return encrypted; // fallback
        const combined = new Uint8Array(base64ToArrayBuffer(encrypted));
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.storeEncryptionKey,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    /**
     * Remove all persisted ratchet keys (used only when identity keys are regenerated).
     */
private async _clearRatchetKeysFromStorage(): Promise<void> {
        if (!this.currentUserId) return;
        try {
            await KeyStorageService.clearAllPreKeys(this.currentUserId);
        } catch (error) {
            Logger.warn('Failed to clear persisted pre-keys:', error);
        }
    }

    /**
     * Upload the pre-key bundle to the server.
     */
    async uploadPreKeyBundle(bundle: PreKeyBundleDTO, authToken: string): Promise<void> {
        const res = await fetch(`${BASE_API_URL}/api/users/pre-key-bundle`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${authToken}`,
            },
            body: JSON.stringify(bundle),
        });
        if (!res.ok) {
            throw new Error('Failed to upload pre-key bundle');
        }
        Logger.cryptoEvent('SessionRatchetService.uploadPreKeyBundle', {});
    }

    /**
     * Check if the one-time pre-key pool is low and upload a fresh batch if needed.
     */
    async refreshPreKeysIfNeeded(minCount: number, authToken: string): Promise<void> {
        if (this.getOneTimePreKeyCount() < minCount) {
            const newBundle = await this.generatePreKeyBundle(100);
            await this.uploadPreKeyBundle(newBundle, authToken);
            Logger.cryptoEvent('SessionRatchetService.refreshPreKeys', {
                newCount: 100,
            });
        }
    }
}

// ── Utility functions (local to this file) ──────────────

function arrayBufferToBase64(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

/** SHA-256 hash prefix (16 hex chars) of public identity key material, for safe logging. */
async function hashForLog(value: string): Promise<string> {
    try {
        const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
        return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
    } catch {
        return `${value.length}chars`;
    }
}

/** Determine if a parsed ratchet header is a per-recipient map (object of userId -> header) vs a single header. */
function isPerRecipientMap(parsed: any): boolean {
    return !!parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('body' in parsed);
}

/**
 * Convert a raw binary string (each char code 0-255, as produced by the Signal
 * library's `uint8ArrayToString`) back into an ArrayBuffer. This is binary-safe
 * and preserves any null bytes, which is exactly what we need before base64-encoding.
 */
function binaryStringToArrayBuffer(str: string): ArrayBuffer {
    let i = 0;
    const len = str.length;
    const bytes = new Uint8Array(len);
    for (i = 0; i < len; i++) {
        const code = str.charCodeAt(i);
        if (code > 0xff) throw new RangeError('illegal char code: ' + code);
        bytes[i] = code;
    }
    return bytes.buffer;
}

const sessionRatchetService = new SessionRatchetService();
export default sessionRatchetService;

