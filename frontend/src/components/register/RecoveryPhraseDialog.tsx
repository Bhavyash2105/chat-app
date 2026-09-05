import React, {useState} from "react";
import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Checkbox,
    FormControlLabel,
} from "@mui/material";
import styles from "./Register.module.scss";

interface RecoveryPhraseDialogProps {
    phrase: string;
    open: boolean;
    onConfirmed: () => void;
}

const RecoveryPhraseDialog = (props: RecoveryPhraseDialogProps) => {
    const [hasSaved, setHasSaved] = useState<boolean>(false);
    const [copyLabel, setCopyLabel] = useState<string>("Copy to Clipboard");

    const words = props.phrase.split(" ");

    const onCopy = async () => {
        try {
            await navigator.clipboard.writeText(props.phrase);
            setCopyLabel("Copied!");
            setTimeout(() => setCopyLabel("Copy to Clipboard"), 3000);
        } catch {
            // Fallback for non-HTTPS
            const textarea = document.createElement("textarea");
            textarea.value = props.phrase;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand("copy");
            document.body.removeChild(textarea);
            setCopyLabel("Copied!");
            setTimeout(() => setCopyLabel("Copy to Clipboard"), 3000);
        }
    };

    return (
        <Dialog open={props.open} maxWidth="sm" fullWidth>
            <DialogTitle sx={{textAlign: "center", fontWeight: "bold"}}>
                🔐 Your Recovery Phrase
            </DialogTitle>
            <DialogContent>
                <DialogContentText sx={{mb: 2, color: "#d32f2f", fontWeight: "bold", textAlign: "center"}}>
                    ⚠️ This is the ONLY way to recover your encrypted messages if you lose your password.
                    Write it down or store it somewhere safe. Never share it with anyone.
                </DialogContentText>

                <div style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr 1fr",
                    gap: "8px",
                    padding: "16px",
                    backgroundColor: "#f5f5f5",
                    borderRadius: "8px",
                    marginBottom: "16px",
                }}>
                    {words.map((word, index) => (
                        <div key={index} style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                            fontSize: "0.9rem",
                        }}>
                            <span style={{color: "#888", minWidth: "20px", textAlign: "right"}}>
                                {index + 1}.
                            </span>
                            <span style={{fontWeight: 600}}>{word}</span>
                        </div>
                    ))}
                </div>

                <div style={{textAlign: "center", marginBottom: "12px"}}>
                    <Button variant="outlined" size="small" onClick={onCopy}>
                        {copyLabel}
                    </Button>
                </div>

                <FormControlLabel
                    control={
                        <Checkbox
                            checked={hasSaved}
                            onChange={(e) => setHasSaved(e.target.checked)}
                            color="primary"
                        />
                    }
                    label="I have saved my recovery phrase in a safe place and understand that without it, data recovery is impossible if I lose my password."
                    sx={{alignItems: "flex-start", "& .MuiFormControlLabel-label": {fontSize: "0.85rem"}}}
                />
            </DialogContent>
            <DialogActions sx={{justifyContent: "center", pb: 2}}>
                <Button
                    variant="contained"
                    color="primary"
                    disabled={!hasSaved}
                    onClick={props.onConfirmed}
                    size="large"
                >
                    I've Saved It — Continue
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default RecoveryPhraseDialog;

