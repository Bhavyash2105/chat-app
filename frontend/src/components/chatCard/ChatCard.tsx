import {Avatar, Badge} from "@mui/material";
import React, {useEffect, useState} from "react";
import {getChatName, getInitialsFromName, transformDateToString} from "../utils/Utils";
import styles from './ChatCard.module.scss';
import {ChatDTO} from "../../redux/chat/ChatModel";
import {useSelector} from "react-redux";
import {RootState} from "../../redux/Store";
import {MessageDTO} from "../../redux/message/MessageModel";
import SessionRatchetService from "../../services/SessionRatchetService";

interface ChatCardProps {
    chat: ChatDTO;
}

const ChatCard = (props: ChatCardProps) => {

    const authState = useSelector((state: RootState) => state.auth);
    const [decryptedPreview, setDecryptedPreview] = useState<string | null>("...");

    const name: string = getChatName(props.chat, authState.reqUser);
    const initials: string = getInitialsFromName(name);
    const sortedMessages: MessageDTO[] = [...props.chat.messages].sort((a, b) => +new Date(a.timeStamp) - +new Date(b.timeStamp));
    const lastMessage: MessageDTO | undefined = sortedMessages.length > 0 ? sortedMessages[sortedMessages.length - 1] : undefined;

    useEffect(() => {
        if (!lastMessage || !authState.reqUser) {
            setDecryptedPreview(null);
            return;
        }

        if (!lastMessage.isEncrypted) {
            setDecryptedPreview(lastMessage.content ?? "");
            return;
        }

        if (!lastMessage.ratchetHeader) {
            setDecryptedPreview("🔒");
            return;
        }

        const isOwnMessage = lastMessage.user.id === authState.reqUser.id;
        const localPlaintext = (lastMessage as MessageDTO & { __localPlaintext?: string }).__localPlaintext;

        if (isOwnMessage) {
            if (localPlaintext) {
                setDecryptedPreview(localPlaintext);
                return;
            }

            let cancelled = false;
            const loadCachedOwnMessage = async () => {
                try {
                    const cached = await SessionRatchetService.getCachedOwnMessage(lastMessage.id.toString());
                    if (!cancelled) {
                        if (cached) {
                            setDecryptedPreview(cached);
                        } else {
                            setDecryptedPreview("🔒");
                        }
                    }
                } catch {
                    if (!cancelled) setDecryptedPreview("🔒");
                }
            };
            loadCachedOwnMessage();
            return () => { cancelled = true; };
        }

        let cancelled = false;
        const doDecrypt = async () => {
            try {
                const plaintext = await SessionRatchetService.ratchetDecrypt(
                    lastMessage.ratchetHeader!,
                    lastMessage.content ?? "",
                    lastMessage.user.id.toString(),
                    lastMessage.id.toString()
                );
                if (!cancelled) setDecryptedPreview(plaintext);
            } catch {
                if (!cancelled) setDecryptedPreview("🔒");
            }
        };
        doDecrypt();

        return () => { cancelled = true; };
    }, [lastMessage, authState.reqUser]);

    const previewText = decryptedPreview ?? "";
    const lastMessageContent: string = previewText.length > 25 ? previewText.slice(0, 25) + "..." : previewText;
    const lastMessageName: string = lastMessage ? lastMessage.user.fullName === authState.reqUser?.fullName ? "You" : lastMessage.user.fullName : "";
    const lastMessageString: string = lastMessage ? lastMessageName + ": " + lastMessageContent : "";
    const lastDate: string = lastMessage ? transformDateToString(new Date(lastMessage.timeStamp)) : "";
    const numberOfReadMessages: number = props.chat.messages.filter(msg =>
        msg.user.id === authState.reqUser?.id || msg.readBy.includes(authState.reqUser!.id)).length;
    const numberOfUnreadMessages: number = props.chat.messages.length - numberOfReadMessages;

    return (
        <div className={styles.chatCardOuterContainer}>
            <div className={styles.chatCardAvatarContainer}>
                <Avatar sx={{
                    width: '2.5rem',
                    height: '2.5rem',
                    fontSize: '1rem',
                    mr: '0.75rem'
                }}>
                    {initials}
                </Avatar>
            </div>
            <div className={styles.chatCardContentContainer}>
                <div className={styles.chatCardContentInnerContainer}>
                    <p className={styles.chatCardLargeTextContainer}>{name}</p>
                    <p className={styles.chatCardSmallTextContainer}>{lastDate}</p>
                </div>
                <div className={styles.chatCardContentInnerContainer}>
                    <p className={styles.chatCardSmallTextContainer}>{lastMessageString}</p>
                    {<Badge badgeContent={numberOfUnreadMessages} color='primary' sx={{mr: '0.75rem'}}/>}
                </div>
            </div>
        </div>
    );
};

export default ChatCard;