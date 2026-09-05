import styles from './Register.module.scss'
import {useNavigate, useLocation} from "react-router-dom";
import React, {Dispatch, useCallback, useEffect, useState} from "react";
import {useDispatch, useSelector} from "react-redux";
import {verifyOtp, currentUser} from "../../redux/auth/AuthAction";
import {Alert, Button, CircularProgress, TextField} from "@mui/material";
import {RootState} from "../../redux/Store";
import {TOKEN} from "../../config/Config";
import RecoveryService from "../../services/RecoveryService";
import KeyManagementService from "../../services/KeyManagementService";
import RecoveryPhraseDialog from "./RecoveryPhraseDialog";

const VerifyOtp = () => {
const [otpCode, setOtpCode] = useState<string>("");
    const [isVerifying, setIsVerifying] = useState<boolean>(false);
    const [showPhraseDialog, setShowPhraseDialog] = useState<boolean>(false);
    const [recoveryPhrase, setRecoveryPhrase] = useState<string>("");
    const [isGeneratingKeys, setIsGeneratingKeys] = useState<boolean>(false);
    const [setupError, setSetupError] = useState<string>("");
    const navigate = useNavigate();
    const location = useLocation();
    const dispatch: Dispatch<any> = useDispatch();
    const token: string | null = localStorage.getItem(TOKEN);
    const authState = useSelector((state: RootState) => state.auth);

const email: string = location.state?.email || "";
    const signupPassword: string = location.state?.password || "";
    const activeToken = authState.otpVerification?.token || token;

    const initE2EEAndGeneratePhrase = useCallback(async () => {
        if (!authState.reqUser || !activeToken || authState.reqUser.email !== email) return;
        setIsGeneratingKeys(true);
        setSetupError("");

        try {
            const userId = authState.reqUser.id.toString();
const password = signupPassword;
            if (!password) {
                console.warn("No signup password available for E2EE key generation");
                setSetupError("Signup password was lost before encryption setup. Please sign in and choose the recovery/new-device flow.");
                return;
            }

await KeyManagementService.initializeOnSignup(userId, password);
            await KeyManagementService.uploadPreKeyBundle(activeToken);

            const phrase = await RecoveryService.generateMnemonic();
            setRecoveryPhrase(phrase);
            setShowPhraseDialog(true);

            console.log("E2EE keys initialized and pre-key bundle uploaded");
        } catch (err) {
            console.error("Failed to initialize E2EE keys after OTP verification:", err);
            setSetupError((err as Error).message || "Failed to initialize encryption keys. Please try signing in again.");
        } finally {
            setIsGeneratingKeys(false);
        }
    }, [authState.reqUser, activeToken, email, signupPassword]);

    const onRecoveryPhraseConfirmed = useCallback(async () => {
        if (!authState.reqUser || !activeToken || !recoveryPhrase) return;

        try {
            const userId = authState.reqUser.id.toString();

            const storedRecord = (await import("../../services/KeyStorageService")).default;
            const record = await storedRecord.getKeyRecord(userId);
            if (!record) throw new Error("No key record found after signup");

const CryptoService = (await import("../../services/CryptoService")).default;
            const password = signupPassword;
            if (!password) {
                console.warn("No signup password available for recovery blob encryption");
                throw new Error("Password not available — cannot encrypt recovery blob");
            }
            const privateKeyBase64 = await CryptoService.decryptPrivateKey(
                { encryptedData: record.encryptedData, iv: record.iv, salt: record.salt },
                password
            );

            // The key record stores the Curve25519 public key (as `publicKey` / `curve25519PublicKey`).
            // We encrypt it alongside the private key in the recovery blob so that after recovery
            // both keys can be restored and the ratchet identity rebuilt.
            const publicKeyBase64 = (record as any).curve25519PublicKey || (record as any).publicKey || "";

            const recoveryBlob = await RecoveryService.encryptPrivateKeyWithMnemonic(
                privateKeyBase64,
                publicKeyBase64,
                recoveryPhrase
            );

            await RecoveryService.uploadRecoveryBlob(recoveryBlob, activeToken);
            RecoveryService.markPhraseShown();

            console.log("Recovery phrase generated and blob uploaded");
        } catch (err) {
            console.error("Failed to upload recovery blob:", err);
            console.warn("Recovery blob upload failed, but account setup continued");
        }

        setShowPhraseDialog(false);
        navigate("/");
    }, [authState.reqUser, activeToken, recoveryPhrase, signupPassword, navigate]);

    const onSubmit = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();

        if (!email) {
            navigate("/signup");
            return;
        }

        setIsVerifying(true);
        setSetupError("");
        try {
            await dispatch(verifyOtp({email, otpCode}));
        } finally {
            // Always stop the loading spinner, even if the backend request
            // returns an error (e.g. stale DB connection) and no token is set.
            setIsVerifying(false);
        }
    };

    useEffect(() => {
        if (authState.otpVerification?.token) {
            dispatch(currentUser(authState.otpVerification.token));
        }
    }, [authState.otpVerification?.token, dispatch]);

    useEffect(() => {
        if (
            authState.reqUser?.email === email &&
            !showPhraseDialog &&
            !isGeneratingKeys &&
            !recoveryPhrase &&
            !setupError
        ) {
            initE2EEAndGeneratePhrase();
        }
    }, [authState.reqUser, email, showPhraseDialog, isGeneratingKeys, recoveryPhrase, setupError, initE2EEAndGeneratePhrase]);

    if (!email) {
        return (
            <div className={styles.outerContainer}>
                <div className={styles.innerContainer}>
                    <p>No signup in progress. Please sign up first.</p>
                    <Button variant="contained" onClick={() => navigate("/signup")}>Go to Sign Up</Button>
                </div>
            </div>
        );
    }

    return (
        <div>
            <div className={styles.outerContainer}>
                <div className={styles.innerContainer}>
                    <p className={styles.text}>Enter the 6-digit code sent to {email}</p>
                    {setupError && <Alert severity="error" sx={{mb: 2}}>{setupError}</Alert>}
                    <form onSubmit={onSubmit}>
                        <div>
                            <TextField
                                className={styles.textInput}
                                id="otpCode"
                                type="text"
                                label="Verification code"
                                variant="outlined"
onChange={(e) => setOtpCode(e.target.value)}
                                value={otpCode}/>
                        </div>
                        <div className={styles.button}>
                            <Button
                                fullWidth
                                variant="contained"
                                size="large"
                                type="submit"
                                disabled={isVerifying || isGeneratingKeys}>
                                {isVerifying ? <CircularProgress size={24}/> : "Verify"}
                            </Button>
                        </div>
                    </form>
                </div>
            </div>

            <RecoveryPhraseDialog
                phrase={recoveryPhrase}
                open={showPhraseDialog}
                onConfirmed={onRecoveryPhraseConfirmed}
            />
        </div>
    );
};

export default VerifyOtp;
