import styles from './Register.module.scss'
import {useNavigate, useLocation} from "react-router-dom";
import React, {Dispatch, useState} from "react";
import {useDispatch} from "react-redux";
import {verifyOtp} from "../../redux/auth/AuthAction";
import {Button, TextField} from "@mui/material";

const VerifyOtp = () => {
    const [otpCode, setOtpCode] = useState<string>("");
    const navigate = useNavigate();
    const location = useLocation();
    const dispatch: Dispatch<any> = useDispatch();

    const email: string = location.state?.email || "";

    const onSubmit = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();

        if (!email) {
            navigate("/signup");
            return;
        }

        await dispatch(verifyOtp({email, otpCode}));
        navigate("/");
    };

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
                                type="submit">
                                Verify
                            </Button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default VerifyOtp;