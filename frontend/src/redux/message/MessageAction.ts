import {MessageDTO, SendMessageRequestDTO} from "./MessageModel";
import {AppDispatch} from "../Store";
import {BASE_API_URL} from "../../config/Config";
import {AUTHORIZATION_PREFIX} from "../Constants";
import * as actionTypes from './MessageActionType';
import {UUID} from "node:crypto";
import SessionRatchetService from "../../services/SessionRatchetService";

const MESSAGE_PATH = 'api/messages';

export const createMessage = (data: SendMessageRequestDTO, token: string, senderPlaintext?: string, tempMessageId?: string) => async (dispatch: AppDispatch): Promise<void> => {
    console.log('[createMessage] Sending message payload:', {
        chatId: data.chatId,
        contentLen: data.content?.length,
        ivLen: data.iv?.length,
        ratchetHeaderLen: data.ratchetHeader?.length,
        encryptionFormat: data.encryptionFormat,
        contentHasNul: data.content ? data.content.indexOf('\u0000') >= 0 : false,
        headerHasNul: data.ratchetHeader ? data.ratchetHeader.indexOf('\u0000') >= 0 : false,
    });
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${MESSAGE_PATH}/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
            body: JSON.stringify(data),
        });

        if (!res.ok) {
            const errText = await res.text();
            console.error('[createMessage] Server returned error', res.status, errText);
            return;
        }

        const resData: MessageDTO = await res.json();
        console.log('[createMessage] Send message SUCCESS:', resData);
        if (senderPlaintext && resData.id) {
            try {
                const realMessageId = resData.id.toString();
                const rekeyed = tempMessageId
                    ? await SessionRatchetService.rekeyCachedOwnMessage(tempMessageId, realMessageId)
                    : false;
                if (!rekeyed) {
                    await SessionRatchetService.cacheOwnSentMessage(realMessageId, senderPlaintext);
                }
            } catch (cacheError) {
                console.error('[createMessage] Failed to cache own plaintext', cacheError);
            }
        }
        dispatch({type: actionTypes.CREATE_NEW_MESSAGE, payload: {
            ...resData,
            __localPlaintext: senderPlaintext,
        }});
    } catch (error: any) {
        console.error('[createMessage] Sending message failed', error);
    }
};

export const getAllMessages = (chatId: UUID, token: string) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${MESSAGE_PATH}/chat/${chatId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            }
        });

        const resData: MessageDTO[] = await res.json();
        console.log('Getting messages: ', resData);
        dispatch({type: actionTypes.GET_ALL_MESSAGES, payload: resData});
    } catch (error: any) {
        console.error('Getting messages failed: ', error);
    }
};
