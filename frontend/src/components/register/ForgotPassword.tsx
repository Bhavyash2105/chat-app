import styles from './Register.module.scss';
import React, {useEffect, useRef, useState} from "react";
import {useNavigate} from "react-router-dom";
import {useDispatch} from "react-redux";
import {Alert, Button, CircularProgress, TextField} from "@mui/material";
import {requestPasswordResetOtp, resetPasswordWithOtp} from "../../redux/auth/AuthAction";
import {AppDispatch} from "../../redux/Store";
import {RECAPTCHA_SITE_KEY} from "../../config/Config";

const ForgotPassword = () => {
    const recaptchaRef = useRef<HTMLDivElement>(null);
    const widgetIdRef = useRef<number | null>(null);
    const captchaSolvedAtRef = useRef<number>(0);

    const [email, setEmail] = useState<string>("");
    const [otpCode, setOtpCode] = useState<string>("");
    const [newPassword, setNewPassword] = useState<string>("");
    const [confirmPassword, setConfirmPassword] = useState<string>("");
    const [step, setStep] = useState<"request" | "verify">("request");
    const [message, setMessage] = useState<string>("");
    const [error, setError] = useState<string>("");
    const [loading, setLoading] = useState<boolean>(false);

    const navigate = useNavigate();
    const dispatch = useDispatch<AppDispatch>();

    useEffect(() => {
        const renderCaptcha = () => {
            if ((window as any).grecaptcha?.render && recaptchaRef.current && widgetIdRef.current === null) {
                widgetIdRef.current = (window as any).grecaptcha.render(recaptchaRef.current, {
                    sitekey: RECAPTCHA_SITE_KEY,
                    callback: () => { captchaSolvedAtRef.current = Date.now(); },
                });
            }
        };

        if ((window as any).grecaptcha?.render) {
            renderCaptcha();
        } else {
            const interval = setInterval(() => {
                if ((window as any).grecaptcha?.render) {
                    renderCaptcha();
                    clearInterval(interval);
                }
            }, 300);
            return () => clearInterval(interval);
        }
    }, []);

    const onRequestOtp = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError("");
        setMessage("");
        const normalizedEmail = email.trim().toLowerCase();

        if (!normalizedEmail) {
            setError("Please enter your email.");
            return;
        }

        let captchaToken = (window as any).grecaptcha?.getResponse(widgetIdRef.current);
        if (captchaToken && widgetIdRef.current !== null &&
            Date.now() - captchaSolvedAtRef.current > 90000) {
            (window as any).grecaptcha?.reset(widgetIdRef.current);
            captchaToken = "";
            setError("The captcha expired. Please complete the new captcha and try again.");
            return;
        }

        if (!captchaToken) {
            setError("Please complete the captcha before requesting a reset code.");
            return;
        }

        setLoading(true);
        try {
            const response = await dispatch(requestPasswordResetOtp({email: normalizedEmail, captchaToken}));
            setEmail(normalizedEmail);
            setMessage(response.message);
            setStep("verify");
        } catch (err: any) {
            setError(err.message || "Unable to request a reset code. Please try again.");
            if (widgetIdRef.current !== null) {
                (window as any).grecaptcha?.reset(widgetIdRef.current);
            }
        } finally {
            setLoading(false);
        }
    };

    const onResetPassword = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError("");
        setMessage("");

        if (otpCode.trim().length !== 6) {
            setError("Please enter the 6-digit code.");
            return;
        }
        if (newPassword.length < 6) {
            setError("New password must be at least 6 characters.");
            return;
        }
        if (newPassword !== confirmPassword) {
            setError("Passwords do not match.");
            return;
        }

        setLoading(true);
        try {
            const response = await dispatch(resetPasswordWithOtp({
                email: email.trim().toLowerCase(),
                otpCode: otpCode.trim(),
                newPassword,
            }));

            navigate("/signin", {
                state: {
                    forceNewDeviceCheck: true,
                    email: email.trim().toLowerCase(),
                    password: newPassword,
                    token: response.token,
                    reason: "Your password was reset. Restore your encryption keys with your recovery phrase to keep reading old messages.",
                },
            });
        } catch (err: any) {
            setError(err.message || "Password reset failed. Check your code and try again.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <div className={styles.outerContainer}>
                <div className={styles.innerContainer}>
                    <h2 style={{textAlign: "center", marginBottom: "1rem"}}>Reset Password</h2>

                    {step === "request" ? (
                        <form onSubmit={onRequestOtp}>
                            <div>
                                <p className={styles.text}>Email</p>
                                <TextField
                                    className={styles.textInput}
                                    id="email"
                                    type="email"
                                    label="Enter your email"
                                    variant="outlined"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                />
                            </div>
                            {error && <Alert severity="error" sx={{mt: 2}}>{error}</Alert>}
                            {message && <Alert severity="info" sx={{mt: 2}}>{message}</Alert>}
                            <div ref={recaptchaRef}></div>
                            <div className={styles.button}>
                                <Button fullWidth variant="contained" size="large" type="submit" disabled={loading}>
                                    {loading ? <CircularProgress size={24}/> : "Send code"}
                                </Button>
                            </div>
                        </form>
                    ) : (
                        <form onSubmit={onResetPassword}>
                            {message && <Alert severity="info" sx={{mb: 2}}>{message}</Alert>}
                            <div>
                                <p className={styles.text}>Verification Code</p>
                                <TextField
                                    className={styles.textInput}
                                    id="otpCode"
                                    type="text"
                                    label="Enter the 6-digit code"
                                    variant="outlined"
                                    value={otpCode}
                                    onChange={(e) => setOtpCode(e.target.value)}
                                />
                            </div>
                            <div>
                                <p className={styles.text}>New Password</p>
                                <TextField
                                    className={styles.textInput}
                                    id="newPassword"
                                    type="password"
                                    label="Enter new password"
                                    variant="outlined"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                />
                            </div>
                            <div>
                                <p className={styles.text}>Confirm New Password</p>
                                <TextField
                                    className={styles.textInput}
                                    id="confirmPassword"
                                    type="password"
                                    label="Confirm new password"
                                    variant="outlined"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                />
                            </div>
                            {error && <Alert severity="error" sx={{mt: 2}}>{error}</Alert>}
                            <div className={styles.button}>
                                <Button fullWidth variant="contained" size="large" type="submit" disabled={loading}>
                                    {loading ? <CircularProgress size={24}/> : "Reset password"}
                                </Button>
                            </div>
                        </form>
                    )}

                    <div className={styles.bottomContainer}>
                        <Button variant='text' size='large' onClick={() => navigate("/signin")}>Back to Sign In</Button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ForgotPassword;
