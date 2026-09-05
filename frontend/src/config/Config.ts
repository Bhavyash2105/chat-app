/**
 * Environment-aware configuration.
 *
 * For production builds, set these at build time (e.g. Vercel / Render):
 *   - REACT_APP_API_URL   → your deployed backend URL, e.g. https://chatapp-backend.onrender.com
 *   - REACT_APP_WS_URL    → (optional) your deployed WebSocket endpoint if it differs from API_URL/ws
 *   - REACT_APP_RECAPTCHA_SITE_KEY → your Google reCAPTCHA v2 site key
 *
 * All values fall back to local development defaults so `npm start` works out of the box.
 */
export const BASE_API_URL: string =
    (process.env.REACT_APP_API_URL as string) || "http://localhost:8080";

/**
 * WebSocket base URL. Defaults to the API host so the realtime channel
 * works on both local dev (localhost:8080) and production (same host).
 */
export const WS_BASE_URL: string =
    (process.env.REACT_APP_WS_URL as string) || BASE_API_URL;

/**
 * Google reCAPTCHA v2 site key. Provide `REACT_APP_RECAPTCHA_SITE_KEY` at build
 * time for production; the value below is the app's real site key that matches
 * the backend `RECAPTCHA_SECRET` (from the Google reCAPTCHA admin console).
 */
export const RECAPTCHA_SITE_KEY: string =
    (process.env.REACT_APP_RECAPTCHA_SITE_KEY as string) ||
    "6LcOcGEtAAAAAF2O7mkInmPfqlrzkilME3GJP1jM";

export const TOKEN = 'token';

