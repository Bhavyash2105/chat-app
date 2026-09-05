import styles from './Register.module.scss'
import {useNavigate} from "react-router-dom";
import React, {Dispatch, useEffect, useRef, useState} from "react";
import {useDispatch} from "react-redux";
import {SignUpRequestDTO} from "../../redux/auth/AuthModel";
import {register} from "../../redux/auth/AuthAction";
import {Button, TextField} from "@mui/material";
// Site key is read from the build-time env var (REACT_APP_RECAPTCHA_SITE_KEY),
// falling back to Google's public test key for local development.
import {RECAPTCHA_SITE_KEY} from "../../config/Config";

declare global {
    interface Window {
        grecaptcha: any;
    }
}

// TODO: Verify email
// TODO: Check if account already exists
// TODO: Show error if something went wrong
const SignUp = () => {

    const recaptchaRef = useRef<HTMLDivElement>(null);
    const widgetIdRef = useRef<number | null>(null);
    // Timestamp (ms) of when the captcha was last solved. reCAPTCHA v2 tokens
    // expire after ~120s; if the user solves it and then takes too long to submit,
    // the backend rejects the token with "timeout-or-duplicate".
    const captchaSolvedAtRef = useRef<number>(0);

    const [createAccountData, setCreateAccountData] = useState<SignUpRequestDTO>({
        fullName: "",
        email: "",
        password: "",
        captchaToken: "",
    });
    const navigate = useNavigate();
    const dispatch: Dispatch<any> = useDispatch();

    useEffect(() => {
        const renderCaptcha = () => {
            // @ts-ignore
            if (window.grecaptcha && window.grecaptcha.render && recaptchaRef.current && widgetIdRef.current === null) {
                // @ts-ignore
                widgetIdRef.current = window.grecaptcha.render(recaptchaRef.current, {
                    sitekey: RECAPTCHA_SITE_KEY,
                    callback: () => { captchaSolvedAtRef.current = Date.now(); },
                });
            }
        };

        // @ts-ignore
        if (window.grecaptcha && window.grecaptcha.render) {
            renderCaptcha();
        } else {
            const interval = setInterval(() => {
                // @ts-ignore
                if (window.grecaptcha && window.grecaptcha.render) {
                    renderCaptcha();
                    clearInterval(interval);
                }
            }, 300);
            return () => clearInterval(interval);
        }
    }, []);

    const onSubmit = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();
        const normalizedEmail = createAccountData.email.trim().toLowerCase();

        // @ts-ignore - grecaptcha is loaded globally via the script tag
        let captchaToken = window.grecaptcha?.getResponse(widgetIdRef.current);

        // If the solved captcha is older than ~90s, its token is about to expire.
        // Reset the widget and ask the user to solve the fresh challenge.
        if (captchaToken && widgetIdRef.current !== null &&
            Date.now() - captchaSolvedAtRef.current > 90000) {
            // @ts-ignore
            window.grecaptcha?.reset(widgetIdRef.current);
            captchaToken = "";
            alert("The captcha expired. Please complete the new captcha and try again.");
            return;
        }

        if (!captchaToken) {
            alert("Please complete the captcha before signing up.");
            return;
        }

        await dispatch(register({...createAccountData, email: normalizedEmail, captchaToken}));
        // Pass password via route state instead of window.__signupPassword
        // This avoids exposing the plaintext password on the global window object
        navigate("/verify-otp", {
            state: {
                email: normalizedEmail,
                password: createAccountData.password,
            }
        });
    };

    const onChangeFullName = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setCreateAccountData({...createAccountData, fullName: e.target.value});
    };

    const onChangeEmail = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setCreateAccountData({...createAccountData, email: e.target.value});
    }

    const onChangePassword = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setCreateAccountData({...createAccountData, password: e.target.value});
    };

    const onNavigateToSignIn = () => {
        navigate("/signin");
    }

    return (
        <div>
            <div className={styles.outerContainer}>
                <div className={styles.innerContainer}>
                    <form onSubmit={onSubmit}>
                        <div>
                            <p className={styles.text}>Full Name</p>
                            <TextField
                                className={styles.textInput}
                                id="fullName"
                                type="text"
                                label="Enter your full name"
                                variant="outlined"
                                onChange={onChangeFullName}
                                value={createAccountData.fullName}/>
                        </div>
                        <div>
                            <p className={styles.text}>Email</p>
                            <TextField
                                className={styles.textInput}
                                id="email"
                                type="email"
                                label="Enter your email"
                                variant="outlined"
                                onChange={onChangeEmail}
                                value={createAccountData.email}/>
                        </div>
                        <div>
                            <p className={styles.text}>Password</p>
                            <TextField
                                className={styles.textInput}
                                id="password"
                                type="password"
                                label="Enter your password"
                                variant="outlined"
                                onChange={onChangePassword}
                                value={createAccountData.password}/>
                        </div>
                        <div ref={recaptchaRef}></div>
                        <div className={styles.button}>
                            <Button
                                fullWidth
                                variant="contained"
                                size="large"
                                type="submit">
                                Sign up
                            </Button>
                        </div>
                    </form>
                    <div className={styles.bottomContainer}>
                        <p>Already signed up?</p>
                        <Button variant='text' size='large' onClick={onNavigateToSignIn}>Login</Button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SignUp;
