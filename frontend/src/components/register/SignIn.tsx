import {TOKEN} from "../../config/Config";
import {useDispatch, useSelector} from "react-redux";
import {AuthReducerState, LoginRequestDTO} from "../../redux/auth/AuthModel";
import {useLocation, useNavigate} from "react-router-dom";
import React, {Dispatch, useCallback, useEffect, useRef, useState} from "react";
import {currentUser, loginUser} from "../../redux/auth/AuthAction";
import {RootState} from "../../redux/Store";
import {Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField} from "@mui/material";
import styles from "./Register.module.scss";
import KeyManagementService from "../../services/KeyManagementService";
import RecoveryService from "../../services/RecoveryService";
import KeyStorageService from "../../services/KeyStorageService";
import TelemetryService from "../../services/TelemetryService";
import SessionRatchetService from "../../services/SessionRatchetService";

type SignInRouteState = {
    forceNewDeviceCheck?: boolean;
    email?: string;
    password?: string;
    token?: string;
    reason?: string;
};

// TODO: Show error if something went wrong (like wrong mail/ pw)
const SignIn = () => {

    const [signInData, setSignInData] = useState<LoginRequestDTO>({email: "", password: ""});
    const [errorMessage, setErrorMessage] = useState<string>("");
    const [lockoutCountdown, setLockoutCountdown] = useState<number | null>(null);
    const [showNewDeviceDialog, setShowNewDeviceDialog] = useState<boolean>(false);
    const [newDeviceReason, setNewDeviceReason] = useState<string>("");
    const [showRecoveryInput, setShowRecoveryInput] = useState<boolean>(false);
    const [recoveryPhrase, setRecoveryPhrase] = useState<string>("");
    const [recoveryError, setRecoveryError] = useState<string>("");
    const [recoveryLoading, setRecoveryLoading] = useState<boolean>(false);
    const [newDeviceLoading, setNewDeviceLoading] = useState<boolean>(false);
    const navigate = useNavigate();
    const location = useLocation();
    const routeState = location.state as SignInRouteState | null;
    const dispatch: Dispatch<any> = useDispatch();
    const token: string | null = localStorage.getItem(TOKEN);
    const state: AuthReducerState = useSelector((state: RootState) => state.auth);
    const handledLoginTokenRef = useRef<string | null>(null);
    const handledForcedCheckRef = useRef<boolean>(false);

    useEffect(() => {
        if (token) {
            dispatch(currentUser(token));
        }
    }, [token, state.reqUser, dispatch]);

    useEffect(() => {
        if (!routeState?.forceNewDeviceCheck) return;
        setSignInData(prev => ({
            email: routeState.email || prev.email,
            password: routeState.password || prev.password,
        }));
    }, [routeState?.forceNewDeviceCheck, routeState?.email, routeState?.password]);

    const handleLoginSuccess = useCallback(async (userId: string, password: string, jwtToken: string, forcedReason?: string) => {
        const loadResult = await KeyManagementService.loadOnSignIn(userId, password);
        if (loadResult.status === "new-device") {
            setNewDeviceReason(
                forcedReason ||
                (loadResult.reason === "no-local-key"
                    ? "This device has no encryption keys. Messages sent before this login cannot be decrypted here."
                    : "The encryption key could not be decrypted with the provided password (wrong password or keys from a different device). Messages sent before this login cannot be decrypted here.")
            );
            setShowNewDeviceDialog(true);
        } else {
            try {
                await KeyManagementService.uploadPreKeyBundle(jwtToken);
            } catch (error) {
                console.error("Failed to upload pre-key bundle after sign-in:", error);
                setErrorMessage("Signed in, but encryption setup could not publish your pre-key bundle. Please try signing in again.");
                return;
            }
            navigate("/");
        }
    }, [navigate]);

    useEffect(() => {
        if (!routeState?.forceNewDeviceCheck || handledForcedCheckRef.current || !state.reqUser) return;
        const jwtToken = routeState.token || token;
        const password = routeState.password || signInData.password;
        if (!jwtToken || !password) return;

        handledForcedCheckRef.current = true;
        handleLoginSuccess(state.reqUser.id.toString(), password, jwtToken, routeState.reason);
    }, [routeState?.forceNewDeviceCheck, routeState?.token, routeState?.password, routeState?.reason, state.reqUser, token, signInData.password, handleLoginSuccess]);

    useEffect(() => {
        if (state.signin && state.signin.isAuthenticated && state.reqUser) {
            const jwtToken = state.signin.token || token;
            if (jwtToken && handledLoginTokenRef.current !== jwtToken) {
                handledLoginTokenRef.current = jwtToken;
                handleLoginSuccess(state.reqUser.id.toString(), signInData.password, jwtToken);
            }
        }
    }, [state.signin, state.reqUser, signInData.password, token, handleLoginSuccess]);

    useEffect(() => {
        if (state.signin && !state.signin.isAuthenticated) {
            if (state.signin.lockoutTimeRemainingMinutes) {
                setErrorMessage("Account locked. Try again in " + state.signin.lockoutTimeRemainingMinutes + " minute(s).");
                setLockoutCountdown(state.signin.lockoutTimeRemainingMinutes);
            } else {
                setErrorMessage("Invalid email or password.");
                setLockoutCountdown(null);
            }
        }
    }, [state.signin]);

    useEffect(() => {
        if (lockoutCountdown !== null && lockoutCountdown > 0) {
            const interval = setInterval(() => {
                setLockoutCountdown(prev => {
                    if (prev !== null && prev > 1) return prev - 1;
                    if (prev === 1) {
                        setErrorMessage("");
                    }
                    return null;
                });
            }, 60000);
            return () => clearInterval(interval);
        }
    }, [lockoutCountdown]);

    // Option 1: User has recovery phrase
    const handleRecoveryChoice = useCallback(() => {
        setShowRecoveryInput(true);
        setRecoveryError("");
        setRecoveryPhrase("");
    }, []);

    const handleRecoverySubmit = useCallback(async () => {
        if (!state.reqUser || !token) return;
        const trimmedPhrase = recoveryPhrase.trim().toLowerCase();
        if (trimmedPhrase.split(/\s+/).length < 12) {
            setRecoveryError("Please enter your full 12-word recovery phrase.");
            return;
        }
        setRecoveryLoading(true);
        try {
            const userId = state.reqUser.id.toString();
            await RecoveryService.recoverAccess(trimmedPhrase, signInData.password, userId, token);
            setShowNewDeviceDialog(false);
            setShowRecoveryInput(false);
            setRecoveryPhrase("");
            setRecoveryLoading(false);
            navigate("/");
        } catch (err: any) {
            setRecoveryError(err.message || "Recovery failed. Check your phrase and try again.");
            TelemetryService.logDecryptFailure({
                userId: state.reqUser!.id.toString(),
                chatId: "",
                messageId: "",
                failureReason: "recovery-phrase-invalid",
                timestamp: new Date().toISOString(),
            }, token);
            setRecoveryLoading(false);
        }
    }, [state.reqUser, token, recoveryPhrase, signInData.password, navigate]);

    // Option 2: Start fresh — generate new keys with atomic rollback
    const handleNewDeviceConfirm = useCallback(async () => {
        if (!state.reqUser || !token) return;
        const userId = state.reqUser.id.toString();
        const oldRecord = await KeyStorageService.getKeyRecord(userId);
        setNewDeviceLoading(true);
        try {
// Step 1: Generate new keypair in memory only (not persisted to IndexedDB).
            // Atomicity guarantee: if blob upload or pre-key bundle upload fails, IndexedDB
            // still holds the old record (or no record, which is fine for a new device).
            const { record: newRecord } = await KeyManagementService.regenerateKeysWithoutPersist(userId, signInData.password);

            // Step 2: Generate new recovery phrase + blob
            const phrase = await RecoveryService.generateMnemonic();
            const CryptoService = (await import("../../services/CryptoService")).default;
            const privateKeyBase64 = await CryptoService.decryptPrivateKey(
                { encryptedData: newRecord.encryptedData, iv: newRecord.iv, salt: newRecord.salt },
                signInData.password
            );
const publicKeyBase64 = newRecord.curve25519PublicKey || newRecord.publicKey || "";
            const recoveryBlob = await RecoveryService.encryptPrivateKeyWithMnemonic(privateKeyBase64, publicKeyBase64, phrase);

            // Step 3: Upload recovery blob FIRST (before pre-key bundle)
            await RecoveryService.uploadRecoveryBlob(recoveryBlob, token);

            // Step 4: Upload the new pre-key bundle SECOND (awaited, not fire-and-forget dispatch)
            await KeyManagementService.uploadPreKeyBundle(token, newRecord.curve25519PublicKey);

            // Step 4b: Wipe stale sessions built under the OLD identity — otherwise old
            // messages (and any that route through the stale chain) stay decryptable,
            // silently defeating "start fresh."
            await SessionRatchetService.clearAllPersistedSessionsForIdentityRegen();


            // Step 5: BOTH network calls succeeded — NOW persist to IndexedDB (atomic commit)
            await KeyManagementService.persistKeyRecord(newRecord);

            // Step 6: Mark phrase as shown and navigate home
            RecoveryService.markPhraseShown();
            setShowNewDeviceDialog(false);
            setNewDeviceLoading(false);
            alert(
                "YOUR PREVIOUS RECOVERY PHRASE NO LONGER WORKS.\n\n" +
                "Your encryption keys have been regenerated.\n\n" +
                "Your NEW recovery phrase is:\n\n" + phrase +
                "\n\nWrite this down. It will not be shown again."
            );
            navigate("/");
        } catch (err) {
            console.error("Failed:", err);
            // Rollback: restore the old key record if it existed
            if (oldRecord) {
                try {
                    await KeyManagementService.restoreFromKeyRecord(oldRecord, signInData.password);
                } catch (restoreErr) {
                    console.error("Failed to restore old key record during rollback:", restoreErr);
                }
            }
            setShowNewDeviceDialog(false);
            setNewDeviceLoading(false);
            setErrorMessage("Failed to initialize encryption keys.");
        }
    }, [state.reqUser, token, signInData.password, navigate]);

    const handleNewDeviceCancel = useCallback(() => {
        setShowNewDeviceDialog(false);
        setShowRecoveryInput(false);
        setRecoveryPhrase("");
        setRecoveryError("");
        localStorage.removeItem(TOKEN);
        navigate("/signin");
    }, [navigate]);

    const onSubmit = (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrorMessage("");
        setLockoutCountdown(null);
        dispatch(loginUser(signInData));
    };

const onChangeEmail = (e: React.ChangeEvent<HTMLInputElement>) => { setSignInData({...signInData, email: e.target.value}); };
    const onChangePassword = (e: React.ChangeEvent<HTMLInputElement>) => { setSignInData({...signInData, password: e.target.value}); };
    const onClickCreateNewAccount = () => { navigate("/signup"); };
    const onForgotPassword = () => { navigate("/forgot-password"); };

    return (
        <div>
            <div className={styles.outerContainer}>
                <div className={styles.innerContainer}>
                    <form onSubmit={onSubmit}>
                        <div>
                            <p className={styles.text}>Email</p>
                            <TextField className={styles.textInput} id="email" type="email" label="Enter your email" variant="outlined" onChange={onChangeEmail} value={signInData.email}/>
                        </div>
                        <div>
                            <p className={styles.text}>Password</p>
                            <TextField className={styles.textInput} id="password" type="password" label="Enter your password" variant="outlined" onChange={onChangePassword} value={signInData.password}/>
                        </div>
                        {errorMessage && (<p style={{color: "#d32f2f", marginTop: "8px"}}>{errorMessage}</p>)}
                        {lockoutCountdown !== null && lockoutCountdown > 0 && (<p style={{color: "#d32f2f", fontSize: "0.85rem", marginTop: "4px"}}>Lockout ends in ~{lockoutCountdown} minute(s)</p>)}
                        <div className={styles.button}>
                            <Button fullWidth variant="contained" size="large" type="submit">Sign in</Button>
                        </div>
                        <div style={{marginTop: "8px", textAlign: "center"}}>
                            <p style={{fontSize: "0.75rem", color: "#888"}}>Messages are encrypted end-to-end. Password loss = permanent message history loss.</p>
                            <p style={{fontSize: "0.75rem", color: "#888", marginTop: "4px"}}>Encrypted chats are currently only accessible on the device where you signed up. Multi-device support is coming.</p>
                        </div>
                    </form>
                    <div className={styles.bottomContainer}>
                        <p>Create new account</p>
                        <Button variant="text" size="large" onClick={onClickCreateNewAccount}>Signup</Button>
                    </div>
                    <div style={{textAlign: "center", marginTop: "0.5rem"}}>
                        <Button variant="text" size="small" onClick={onForgotPassword} style={{fontSize: "0.8rem"}}>Forgot password?</Button>
                    </div>
                </div>
            </div>

            <Dialog open={showNewDeviceDialog} onClose={handleNewDeviceCancel} maxWidth="sm" fullWidth>
                <DialogTitle>New Device Detected</DialogTitle>
                <DialogContent>
                    {!showRecoveryInput ? (
                        <>
                            <DialogContentText>{newDeviceReason}</DialogContentText>
                            <DialogContentText sx={{mt: 2, fontWeight: "bold"}}>If you have your recovery phrase, you can restore your encryption keys and keep reading old messages.</DialogContentText>
                            <DialogContentText sx={{mt: 1}}>If you don't have one, you'll need to generate new keys - messages sent before this login will become permanently unreadable.</DialogContentText>
                        </>
                    ) : (
                        <>
                            <DialogContentText sx={{mb: 2}}>Enter your 12-word recovery phrase to restore your encryption keys.</DialogContentText>
                            <TextField
                                autoFocus id="recoveryPhraseInput" type="text" label="Recovery phrase" fullWidth variant="outlined"
                                multiline rows={3} value={recoveryPhrase}
                                onChange={(e) => setRecoveryPhrase(e.target.value)}
                                placeholder="word1 word2 word3 ..." sx={{mb: 1}}/>
                            {recoveryError && (<DialogContentText sx={{color: "#d32f2f", fontSize: "0.85rem"}}>{recoveryError}</DialogContentText>)}
                        </>
                    )}
                </DialogContent>
                <DialogActions>
                    {!showRecoveryInput ? (
                        <>
                            <Button onClick={handleNewDeviceCancel} color="secondary">Cancel</Button>
                            <Button onClick={handleRecoveryChoice} variant="outlined" color="primary">I have my recovery phrase</Button>
                            <Button onClick={handleNewDeviceConfirm} variant="contained" color="warning" disabled={newDeviceLoading}>{newDeviceLoading ? "Generating keys..." : "Start fresh (old messages lost)"}</Button>
                        </>
                    ) : (
                        <>
                            <Button onClick={() => { setShowRecoveryInput(false); setRecoveryError(""); }} color="secondary">Back</Button>
                            <Button onClick={handleRecoverySubmit} variant="contained" color="primary" disabled={recoveryLoading}>{recoveryLoading ? "Restoring..." : "Restore keys"}</Button>
                        </>
                    )}
                </DialogActions>
            </Dialog>
        </div>
    );
};

export default SignIn;
