import {UUID} from "node:crypto";
import {UserDTO} from "../auth/AuthModel";
import {ChatDTO} from "../chat/ChatModel";

export interface MessageDTO {
    id: UUID;
    content?: string | null;
    timeStamp: string;
    user: UserDTO;
    readBy: UUID[];
    iv?: string | null;
    isEncrypted?: boolean;
    /** JSON-encoded ratchet header for Double Ratchet messages */
    ratchetHeader?: string | null;
    /** "ratchet" = Double Ratchet */
    encryptionFormat?: string | null;
}

export interface WebSocketMessageDTO {
    id: UUID;
    content: string;
    timeStamp: string;
    user: UserDTO;
    chat: ChatDTO;
    iv?: string | null;
    isEncrypted?: boolean;
    ratchetHeader?: string | null;
    encryptionFormat?: string | null;
}

export interface SendMessageRequestDTO {
    chatId: UUID;
    content?: string | null;
    iv?: string | null;
    ratchetHeader?: string | null;
    encryptionFormat?: string | null;
}

export type MessageReducerState = {
    messages: MessageDTO[];
    newMessage: MessageDTO | null;
}
