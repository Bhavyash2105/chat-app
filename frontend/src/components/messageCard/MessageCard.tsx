import {MessageDTO} from "../../redux/message/MessageModel";
import {UserDTO} from "../../redux/auth/AuthModel";
import styles from './MessageCard.module.scss';
import {Button, Chip} from "@mui/material";
import React, {useEffect, useState} from "react";
import {getDateFormat} from "../utils/Utils";
import SessionRatchetService, {IdentityChangedError} from "../../services/SessionRatchetService";
import TelemetryService from "../../services/TelemetryService";
import {TOKEN} from "../../config/Config";

interface MessageCardProps {
    message: MessageDTO;
    reqUser: UserDTO | null;
    isNewDate: boolean;
    isGroup: boolean;
}

const MessageCard = (props: MessageCardProps) => {

    
    const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
    const [decryptError, setDecryptError] = useState<boolean>(false);
    const [identityChanged, setIdentityChanged] = useState<boolean>(false);
    const [retryTick, setRetryTick] = useState<number>(0);

    const isOwnMessage = props.message.user.id === props.reqUser?.id;
    const isRatchetMessage = props.message.encryptionFormat === 'ratchet' || !!props.message.ratchetHeader;
    const date: Date = new Date(props.message.timeStamp);
    const hours = date.getHours() > 9 ? date.getHours().toString() : "0" + date.getHours();
    const minutes = date.getMinutes() > 9 ? date.getMinutes().toString() : "0" + date.getMinutes();

    useEffect(() => {
        const localPlaintext = (props.message as MessageDTO & { __localPlaintext?: string }).__localPlaintext;
        if (isOwnMessage) {
            if (localPlaintext) {
                setDecryptedContent(localPlaintext);
                setDecryptError(false);
                return;
            }

            let cancelled = false;
            const loadCachedOwnMessage = async () => {
                try {
                    const cached = await SessionRatchetService.getCachedOwnMessage(props.message.id.toString());
                    if (!cancelled) {
                        if (cached) {
                            setDecryptedContent(cached);
                            setDecryptError(false);
                        } else {
                            setDecryptError(true);
                        }
                    }
                } catch (error) {
                    if (!cancelled) {
                        setDecryptError(true);
                        console.error('[MessageCard] failed to load own cached message', error);
                    }
                }
            };
            void loadCachedOwnMessage();
            return () => {
                cancelled = true;
            };
        }

        if (isRatchetMessage && props.reqUser) {
            const senderUserId = props.message.user.id.toString();
            const myUserId = props.reqUser.id.toString();
            if (!props.message.ratchetHeader) {
                setDecryptError(true);
                TelemetryService.logDecryptFailure({
                    userId: myUserId,
                    chatId: "",
                    messageId: props.message.id.toString(),
                    failureReason: "missing-ratchet-header",
                    timestamp: new Date().toISOString(),
                }, null);
                return;
            }

            const doRatchetDecrypt = async () => {
                let headerKind = 'unknown';
                try {
                    const parsed = JSON.parse(props.message.ratchetHeader!);
                    headerKind = (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('body' in parsed))
                        ? `map[${Object.keys(parsed).join(',')}]` : 'single';
                } catch { headerKind = 'unparseable'; }
                console.log('[MessageCard] decrypting encrypted message', {
                    messageId: props.message.id.toString(),
                    senderUserId,
                    myUserId,
                    isOwn: isOwnMessage,
                    contentLen: (props.message.content || '').length,
                    headerKind,
                    headerSlice: props.message.ratchetHeader!.slice(0, 120),
                });
                
                try {
                    const plaintext = await SessionRatchetService.ratchetDecrypt(
                        props.message.ratchetHeader!,
                        props.message.content || '',
                        senderUserId,
                        props.message.id.toString()
                    );
                    console.log('[MessageCard] decrypt SUCCESS', {
                        messageId: props.message.id.toString(),
                        isOwn: isOwnMessage,
                        plaintextLen: plaintext.length,
                    });
                    setDecryptedContent(plaintext);
                } catch (e) {
                    console.error('[MessageCard] decrypt FAILED', {
                        messageId: props.message.id.toString(),
                        isOwn: isOwnMessage,
                        senderUserId,
                        headerKind,
                        error: (e as Error).message,
                    });
                    if (e instanceof IdentityChangedError) {
                        setIdentityChanged(true);
                        setDecryptError(true);
                        TelemetryService.logDecryptFailure({
                            userId: myUserId,
                            chatId: "",
                            messageId: props.message.id.toString(),
                            failureReason: "identity-changed",
                            timestamp: new Date().toISOString(),
                        }, null);
                        return;
                    }
                    setDecryptError(true);
                    TelemetryService.logDecryptFailure({
                        userId: myUserId,
                        chatId: "",
                        messageId: props.message.id.toString(),
                        failureReason: "ratchet-decrypt-threw",
                        timestamp: new Date().toISOString(),
                    }, null);
                }
            };
            void doRatchetDecrypt();
            return;
        }

        setDecryptedContent(null);
        setDecryptError(false);
    }, [props.message, props.reqUser, isOwnMessage, isRatchetMessage, retryTick]);

    const onAcceptNewIdentity = async () => {
        const token = localStorage.getItem(TOKEN);
        if (!token) return;
        try {
            await SessionRatchetService.acceptNewIdentityAndReset(props.message.user.id.toString(), token);
            setIdentityChanged(false);
            setDecryptError(false);
            setRetryTick(t => t + 1);
        } catch (err) {
            console.error('[MessageCard] failed to accept new identity', err);
        }
    };

    const displayContent = isOwnMessage
        ? decryptedContent ?? (decryptError ? "🔒 Cannot decrypt" : "🔒 Loading...")
        : isRatchetMessage
            ? decryptedContent ?? (decryptError ? "🔒 Cannot decrypt" : "🔒 Decrypting...")
            : props.message.content ?? "";

    const label: React.ReactElement = (
        <div className={styles.bubbleContainer}>
            {props.isGroup && !isOwnMessage && <h4 className={styles.contentContainer}>{props.message.user.fullName}:</h4>}
            <p className={styles.contentContainer}>{displayContent}</p>
            {identityChanged && !isOwnMessage && (
                <Button size="small" variant="outlined" color="warning" onClick={onAcceptNewIdentity} sx={{mt: 0.5}}>
                    Trust new security code
                </Button>
            )}
            <p className={styles.timeContainer}>{hours + ":" + minutes}</p>
        </div>
    );

    const dateLabel: React.ReactElement = (
      <p>{getDateFormat(date)}</p>
    );

    return (
        <div className={styles.messageCardInnerContainer}>
            {props.isNewDate && <div className={styles.date}>{<Chip label={dateLabel}
                                                                    sx={{height: 'auto', width: 'auto', backgroundColor: '#faebd7'}}/>}</div>}
            <div className={isOwnMessage ? styles.ownMessage : styles.othersMessage}>
                <Chip label={label}
                      sx={{height: 'auto', width: 'auto', backgroundColor: isOwnMessage ? '#d3fdd3' : 'white', ml: '0.75rem'}}/>
            </div>
        </div>
    );
};

export default MessageCard;
