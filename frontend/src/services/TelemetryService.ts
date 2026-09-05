import {BASE_API_URL} from "../config/Config";
import {AUTHORIZATION_PREFIX} from "../redux/Constants";

export interface DecryptFailureEvent {
    userId: string;
    chatId: string;
    messageId: string;
    failureReason: "missing-iv" | "missing-encrypted-key" | "missing-ratchet-header" | "decrypt-threw" | "private-key-not-loaded" | "recovery-phrase-invalid" | "ratchet-decrypt-threw" | "identity-changed";
    timestamp: string;
}

class TelemetryService {
    async logDecryptFailure(event: DecryptFailureEvent, token: string | null): Promise<void> {
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
        };
        if (token) {
            headers["Authorization"] = `${AUTHORIZATION_PREFIX}${token}`;
        }

        try {
            await fetch(`${BASE_API_URL}/api/telemetry/decrypt-failure`, {
                method: "POST",
                headers,
                body: JSON.stringify(event),
            });
            console.warn("[Telemetry] Decrypt failure logged:", event.failureReason, "msg:", event.messageId);
        } catch (err) {
            // Telemetry must never throw — fire-and-forget
            console.error("[Telemetry] Failed to send decrypt failure event:", err);
        }
    }
}

const telemetryService = new TelemetryService();
export default telemetryService;

