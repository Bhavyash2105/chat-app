import React, {Dispatch, useEffect, useState} from "react";
import {useDispatch, useSelector} from "react-redux";
import {RootState} from "../../redux/Store";
import {AuthReducerState, UpdateUserRequestDTO, PasswordChangeRequestDTO} from "../../redux/auth/AuthModel";
import {TOKEN} from "../../config/Config";
import {changePassword, currentUser, updateUser} from "../../redux/auth/AuthAction";
import WestIcon from '@mui/icons-material/West';
import {Avatar, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, IconButton, TextField} from "@mui/material";
import CreateIcon from '@mui/icons-material/Create';
import CheckIcon from '@mui/icons-material/Check';
import styles from './Profile.module.scss';
import CloseIcon from '@mui/icons-material/Close';
import KeyManagementService from "../../services/KeyManagementService";
import RecoveryPhraseDialog from "../register/RecoveryPhraseDialog";


interface ProfileProps {
    onCloseProfile: () => void;
    initials: string;
}

const Profile = (props: ProfileProps) => {

    const [isEditName, setIsEditName] = useState<boolean>(false);
    const [fullName, setFullName] = useState<string | null>(null);
    const [oldPassword, setOldPassword] = useState<string>("");
    const [newPassword, setNewPassword] = useState<string>("");
    const [showPasswordForm, setShowPasswordForm] = useState<boolean>(false);
    const [passwordMessage, setPasswordMessage] = useState<string>("");
    const [showRegenDialog, setShowRegenDialog] = useState<boolean>(false);
    const [regenPassword, setRegenPassword] = useState<string>("");
    const [regenLoading, setRegenLoading] = useState<boolean>(false);
    const [recoveryPhrase, setRecoveryPhrase] = useState<string>("");
    const [showRecoveryPhraseDialog, setShowRecoveryPhraseDialog] = useState<boolean>(false);
    const dispatch: Dispatch<any> = useDispatch();
    const auth: AuthReducerState = useSelector((state: RootState) => state.auth);
    const token: string | null = localStorage.getItem(TOKEN);

    useEffect(() => {
        if (auth.reqUser) {
            setFullName(auth.reqUser.fullName);
        }
    }, [auth.reqUser]);

    useEffect(() => {
        if (token && auth.updateUser) {
            dispatch(currentUser(token));
        }
    }, [auth.updateUser, token, dispatch]);

    const onEditName = () => {
        setIsEditName(true);
    };

    const onUpdateUser = () => {
        if (fullName && token) {
            const data: UpdateUserRequestDTO = {
                fullName: fullName,
            };
            setFullName(fullName);
            dispatch(updateUser(data, token));
            setIsEditName(false);
        }
    };

    const onCancelUpdate = () => {
        if (auth.reqUser) {
            setFullName(auth.reqUser?.fullName);
        }
        setIsEditName(false);
    };

    const onChangeFullName = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setFullName(e.target.value);
    };

    const onChangeOldPassword = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setOldPassword(e.target.value);
    };

    const onChangeNewPassword = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setNewPassword(e.target.value);
    };

    const onChangeRegenPassword = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
        setRegenPassword(e.target.value);
    };

    const onTogglePasswordForm = () => {
        setShowPasswordForm(!showPasswordForm);
        setPasswordMessage("");
        setOldPassword("");
        setNewPassword("");
    };

    const onChangePasswordSubmit = async () => {
        if (!token || !auth.reqUser) return;
        if (!oldPassword || !newPassword) {
            setPasswordMessage("Both fields are required.");
            return;
        }

        try {
            const userId = auth.reqUser.id.toString();

            await KeyManagementService.changePassword(userId, oldPassword, newPassword);

            const data: PasswordChangeRequestDTO = { oldPassword, newPassword };
            dispatch(changePassword(data, token));

            setPasswordMessage("Password changed successfully. Your encryption keys have been re-encrypted.");
            setOldPassword("");
            setNewPassword("");
        } catch (err: any) {
            setPasswordMessage(err.message || "Failed to change password. Check your old password.");
        }
    };

    const onRegenKeysClick = () => {
        setShowRegenDialog(true);
        setRegenPassword("");
    };

    const onRegenKeysConfirm = async () => {
        if (!token || !auth.reqUser || !regenPassword) return;
        setRegenLoading(true);

        // Pre-load dynamic imports (used inside try and catch both)
        const KeyStorageService = (await import("../../services/KeyStorageService")).default;
        const RecoveryService = (await import("../../services/RecoveryService")).default;
        const CryptoService = (await import("../../services/CryptoService")).default;

        // Save old record BEFORE any mutations — this is our rollback snapshot
        const oldRecord = await KeyStorageService.getKeyRecord(auth.reqUser.id.toString());

        try {
            const userId = auth.reqUser.id.toString();

// Step 1: Generate new keypair in memory only.
            // NOT persisted to IndexedDB yet — this is atomicity guarantee #1.
            // If any subsequent step fails, IndexedDB still holds the old key record.
            const { record: newRecord } = await KeyManagementService.regenerateKeysWithoutPersist(userId, regenPassword);

            // Step 2: Generate new 12-word recovery phrase + encrypted recovery blob
            const phrase = await RecoveryService.generateMnemonic();
const privateKeyBase64 = await CryptoService.decryptPrivateKey(
                { encryptedData: newRecord.encryptedData, iv: newRecord.iv, salt: newRecord.salt },
                regenPassword
            );
            const publicKeyBase64 = newRecord.curve25519PublicKey || newRecord.publicKey || "";
            const recoveryBlob = await RecoveryService.encryptPrivateKeyWithMnemonic(privateKeyBase64, publicKeyBase64, phrase);

            // Step 3: Upload recovery blob FIRST (before pre-key bundle).
            // Ordering guarantee: if this fails, the old pre-key bundle on the server still
            // has a valid recovery path for its matching old private key.
            await RecoveryService.uploadRecoveryBlob(recoveryBlob, token);

            // Step 4: Upload the new pre-key bundle to backend AFTER blob upload succeeds.
            await KeyManagementService.uploadPreKeyBundle(token);

            // Step 5: BOTH network calls succeeded.
            // NOW persist the new key record to IndexedDB — atomic commit point.
            // Everything before this is rollback-able.
            await KeyManagementService.persistKeyRecord(newRecord);

            // Step 6: Show recovery phrase dialog with mandatory "I saved this" checkbox.
            // markPhraseShown() is NOT called here — it happens in onRecoveryPhraseConfirmed.
            setRecoveryPhrase(phrase);
            setShowRegenDialog(false);
            setShowRecoveryPhraseDialog(true);
            setRegenLoading(false);
        } catch (err: any) {
            console.error("Failed to regenerate keys:", err);

            // Atomic rollback: restore the OLD key record to IndexedDB and reload into cache.
            // This undoes the in-memory cache mutation from regenerateKeysWithoutPersist.
            if (oldRecord) {
                try {
                    await KeyManagementService.restoreFromKeyRecord(oldRecord, regenPassword);
                } catch (restoreErr) {
                    console.error("Failed to restore old key record during rollback:", restoreErr);
                }
            }

            setShowRegenDialog(false);
            setRegenLoading(false);
            alert("Key regeneration failed: " + (err.message || "Unknown error") + "\n\nYour original keys remain active. Please try again.");
        }
    };

    const onRecoveryPhraseConfirmed = async () => {
        const RecoveryService = (await import("../../services/RecoveryService")).default;
        RecoveryService.markPhraseShown();
        setShowRecoveryPhraseDialog(false);
        setRecoveryPhrase("");
    };

    const onRegenKeysCancel = () => {
        setShowRegenDialog(false);
    };

    return (
        <div className={styles.outerContainer}>
            <div className={styles.headingContainer}>
                <IconButton onClick={props.onCloseProfile}>
                    <WestIcon fontSize='medium'/>
                </IconButton>
                <h2>Profile</h2>
            </div>
            <div className={styles.avatarContainer}>
                <Avatar sx={{width: '12vw', height: '12vw', fontSize: '5vw'}}>{props.initials}</Avatar>
            </div>
            <div className={styles.nameContainer}>
                {!isEditName &&
                    <div className={styles.innerNameStaticContainer}>
                        <p className={styles.nameDistance}>{auth.reqUser?.fullName}</p>
                        <IconButton sx={{mr: '0.75rem'}} onClick={onEditName}>
                            <CreateIcon/>
                        </IconButton>
                    </div>}
                {isEditName &&
                    <div className={styles.innerNameDynamicContainer}>
                        <TextField
                            id="fullName"
                            type="text"
                            label="Enter your full name"
                            variant="outlined"
                            onChange={onChangeFullName}
                            value={fullName}
                            sx={{ml: '0.75rem', width: '70%'}}/>
                        <div>
                            <IconButton onClick={onCancelUpdate}>
                                <CloseIcon/>
                            </IconButton>
                            <IconButton sx={{mr: '0.75rem'}} onClick={onUpdateUser}>
                                <CheckIcon/>
                            </IconButton>
                        </div>
                    </div>}
            </div>
            <div className={styles.infoContainer}>
                <p className={styles.infoText}>This name will appear on your messages</p>
            </div>

            {/* Single-Device Notice */}
            <div className={styles.infoContainer} style={{marginTop: "1rem", textAlign: "center"}}>
                <p style={{fontSize: "0.8rem", color: "#888"}}>
                    📱 Encrypted chats are only accessible on this device. Multi-device support is coming.
                </p>
            </div>

            {/* Key Regeneration Button */}
            <div className={styles.infoContainer} style={{marginTop: "0.5rem"}}>
                <Button variant="outlined" color="warning" fullWidth onClick={onRegenKeysClick}>
                    Regenerate Encryption Keys
                </Button>
            </div>

            {/* Password Change Section */}
            <div className={styles.infoContainer} style={{marginTop: "0.5rem"}}>
                <Button variant="text" fullWidth onClick={onTogglePasswordForm}>
                    {showPasswordForm ? "Cancel Password Change" : "Change Password"}
                </Button>
            </div>

            {showPasswordForm && (
                <div className={styles.infoContainer} style={{padding: "0 0.75rem"}}>
                    <TextField
                        id="oldPassword"
                        type="password"
                        label="Current password"
                        variant="outlined"
                        fullWidth
                        size="small"
                        value={oldPassword}
                        onChange={onChangeOldPassword}
                        sx={{mb: 1}}
                    />
                    <TextField
                        id="newPassword"
                        type="password"
                        label="New password"
                        variant="outlined"
                        fullWidth
                        size="small"
                        value={newPassword}
                        onChange={onChangeNewPassword}
                        sx={{mb: 1}}
                    />
                    <Button variant="contained" fullWidth onClick={onChangePasswordSubmit}>
                        Update Password
                    </Button>
                    {passwordMessage && (
                        <p style={{
                            color: passwordMessage.includes("successfully") ? "green" : "#d32f2f",
                            fontSize: "0.85rem",
                            marginTop: "0.5rem",
                            textAlign: "center"
                        }}>
                            {passwordMessage}
                        </p>
                    )}
                </div>
            )}

            {/* Key Regeneration Confirmation Dialog */}
            <Dialog open={showRegenDialog} onClose={onRegenKeysCancel}>
                <DialogTitle>Regenerate Encryption Keys</DialogTitle>
                <DialogContent>
                    <DialogContentText sx={{mb: 2}}>
                        This will create a new encryption keypair. All previously encrypted messages will become permanently undecryptable on this device.
                        Make sure you want to proceed.
                    </DialogContentText>
                    <TextField
                        autoFocus
                        id="regenPassword"
                        type="password"
                        label="Confirm your password"
                        fullWidth
                        variant="outlined"
                        value={regenPassword}
                        onChange={onChangeRegenPassword}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={onRegenKeysCancel} color="secondary">Cancel</Button>
                    <Button onClick={onRegenKeysConfirm} variant="contained" color="warning" disabled={regenLoading}>
                        {regenLoading ? "Regenerating..." : "Regenerate"}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Recovery Phrase Confirmation Dialog — shown only after both uploads succeed */}
            <RecoveryPhraseDialog
                phrase={recoveryPhrase}
                open={showRecoveryPhraseDialog}
                onConfirmed={onRecoveryPhraseConfirmed}
            />
        </div>
    );
};

export default Profile;

