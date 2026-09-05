import ForumIcon from "@mui/icons-material/Forum";
import React from "react";
import {UserDTO} from "../../redux/auth/AuthModel";
import styles from './WelcomePage.module.scss';

interface WelcomePageProps {
    reqUser: UserDTO | null;
}

const WelcomePage = (props: WelcomePageProps) => {
    return (
        <div className={styles.welcomeContainer}>
            <div className={styles.innerWelcomeContainer}>
                <ForumIcon sx={{
                    width: '10rem',
                    height: '10rem',
                }}/>
                <h1>Welcome, {props.reqUser?.fullName}!</h1>
                <p style={{fontSize: "0.85rem", color: "#888", marginTop: "1rem"}}>
                    📱 Encrypted chats are currently only accessible on the device where you signed up. Multi-device support is coming.
                </p>
            </div>
        </div>
    );
};

export default WelcomePage;