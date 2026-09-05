import {MessageDTO, MessageReducerState} from "./MessageModel";
import {Action} from "../CommonModel";
import * as actionTypes from './MessageActionType';

interface MessageWithLocalPlaintext extends MessageDTO {
    __localPlaintext?: string;
    __wsDelivered?: boolean;
}

const initialState: MessageReducerState = {
    messages: [],
    newMessage: null,
};

const messageReducer = (state: MessageReducerState = initialState, action: Action): MessageReducerState => {
    switch (action.type) {
        case actionTypes.CREATE_NEW_MESSAGE: {
            const incoming = action.payload as MessageWithLocalPlaintext;
            const existingIndex = state.messages.findIndex(m => m.id === incoming.id);
            const withLocalPlaintext = {
                ...incoming,
                __localPlaintext: incoming.__localPlaintext ?? (state.messages[existingIndex] as MessageWithLocalPlaintext | undefined)?.__localPlaintext,
                __wsDelivered: incoming.__wsDelivered ?? (state.messages[existingIndex] as MessageWithLocalPlaintext | undefined)?.__wsDelivered,
            };
            if (existingIndex >= 0) {
                const updated = [...state.messages];
                updated[existingIndex] = withLocalPlaintext as any;
                return {...state, newMessage: withLocalPlaintext as any, messages: updated};
            }
            return {...state, newMessage: withLocalPlaintext as any, messages: [...state.messages, withLocalPlaintext as any]};
        }
        case actionTypes.GET_ALL_MESSAGES: {
            // The DB stores only the SENDER's own ciphertext. For a recipient, the
            // per-recipient ciphertext arrives via WebSocket (RECEIVE_WEBSOCKET_MESSAGE)
            // and must NOT be clobbered by the DB refetch. Preserve the WebSocket-delivered
            // content/iv/ratchetHeader for messages we already appended locally.
            const list = (action.payload as any[]) || [];
            const wsOverrides = new Map<string, any>();
            for (const m of state.messages) {
                if ((m as any).__wsDelivered) {
                    wsOverrides.set(String(m.id), m);
                }
            }
            const merged = list.map((incoming: any) => {
                const override = wsOverrides.get(String(incoming.id));
                if (override) {
                    return {
                        ...incoming,
                        content: override.content,
                        iv: override.iv,
                        ratchetHeader: override.ratchetHeader,
                        __wsDelivered: true,
                        __localPlaintext: override.__localPlaintext ?? incoming.__localPlaintext,
                    };
                }
                return {
                    ...incoming,
                    __localPlaintext: incoming.__localPlaintext,
                };
            });
            return {...state, messages: merged};
        }
        case actionTypes.RECEIVE_WEBSOCKET_MESSAGE: {
            const incoming = action.payload;
            const existing = state.messages.find(m => m.id === incoming.id);
            const withFlag = {
                ...incoming,
                __wsDelivered: true,
                __localPlaintext: (existing as MessageWithLocalPlaintext | undefined)?.__localPlaintext ?? incoming.__localPlaintext,
            };
            const exists = !!existing;
            if (exists) {
                // Replace the existing entry with the WS-delivered (per-recipient) copy.
                return {
                    ...state,
                    messages: state.messages.map(m => m.id === incoming.id ? withFlag : m),
                };
            }
            return {...state, messages: [...state.messages, withFlag]};
        }
    }
    return state;
};

export default messageReducer;