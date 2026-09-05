/**
 * Safe Logger Utility
 *
 * Provides logging helpers that NEVER output plaintext, private keys, recovery phrases,
 * or any sensitive material to the browser console.
 *
 * In production builds, sensitive logging is stripped entirely.
 * In development builds, only metadata (lengths, hashes, status) is logged — never content.
 */

const IS_DEV = process.env.NODE_ENV === 'development';

/**
 * Create a SHA-256 hash of a string for safe debug logging.
 * This allows correlation (e.g., "same key was used") without exposing the actual value.
 */
async function hashForLog(value: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(value);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
}

const Logger = {
    /**
     * Log a message that contains NO sensitive data.
     * Safe for production — but still gated behind dev check to avoid console noise.
     */
    info: (message: string, ...args: any[]) => {
        if (IS_DEV) {
            console.log(`[E2EE] ${message}`, ...args);
        }
    },

    /**
     * Log an error. Error messages often contain stack traces and are safe.
     * Errors are logged in all environments for debugging production issues.
     */
    error: (message: string, ...args: any[]) => {
        console.error(`[E2EE] ${message}`, ...args);
    },

    /**
     * Warn about non-critical issues.
     */
    warn: (message: string, ...args: any[]) => {
        if (IS_DEV) {
            console.warn(`[E2EE] ${message}`, ...args);
        }
    },

    /**
     * Log a key event (key generated, key uploaded, etc.) without exposing key material.
     * Only logs public key metadata (length, hash prefix) in dev mode.
     */
    keyEvent: async (event: string, publicKey?: string) => {
        if (!IS_DEV) return;
        const suffix = publicKey
            ? ` (pubKey: len=${publicKey.length}, hash=0x${await hashForLog(publicKey)})`
            : '';
        console.log(`[E2EE-KEY] ${event}${suffix}`);
    },

    /**
     * Log when a recovery phrase operation occurs — NEVER log the phrase itself.
     * Only log the operation type and a boolean for whether it succeeded.
     */
    recoveryEvent: (event: string, success: boolean) => {
        if (!IS_DEV) return;
        console.log(`[E2EE-RECOVERY] ${event}: ${success ? 'SUCCESS' : 'FAILED'}`);
    },

    /**
     * Log encryption/decryption metadata (counts, sizes) — NEVER log content.
     */
    cryptoEvent: (event: string, metadata: Record<string, number | string>) => {
        if (!IS_DEV) return;
        console.log(`[E2EE-CRYPTO] ${event}`, metadata);
    },
};

export default Logger;

