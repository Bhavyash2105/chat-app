import {AuthReducerState} from "./AuthModel";
import * as actionTypes from './AuthActionType';
import {Action} from "../CommonModel";

const initialState: AuthReducerState = {
    signin: null,
    signup: null,
reqUser: null,
    searchUser: null,
    updateUser: null,
    passwordChanged: null,
    pendingEmail: null,
    otpVerification: null,
    passwordResetOtpRequest: null,
    passwordReset: null,
};

const authReducer = (state: AuthReducerState = initialState, action: Action): AuthReducerState => {
    switch (action.type) {
        case actionTypes.REGISTER:
            return {...state, signup: action.payload};
        case actionTypes.LOGIN_USER:
            return {...state, signin: action.payload};
        case actionTypes.REQ_USER:
            return {...state, reqUser: action.payload};
        case actionTypes.SEARCH_USER:
            return {...state, searchUser: action.payload};
case actionTypes.UPDATE_USER:
            return {...state, updateUser: action.payload};
        case actionTypes.CHANGE_PASSWORD:
            return {...state, passwordChanged: action.payload};
        case actionTypes.VERIFY_OTP:
            return {...state, otpVerification: action.payload};
        case actionTypes.REQUEST_PASSWORD_RESET_OTP:
            return {...state, passwordResetOtpRequest: action.payload};
        case actionTypes.RESET_PASSWORD_WITH_OTP:
            return {...state, passwordReset: action.payload};
        case actionTypes.LOGOUT_USER:
            return {...state, signin: null, signup: null, reqUser: null, passwordChanged: null, pendingEmail: null, otpVerification: null, passwordResetOtpRequest: null, passwordReset: null};
    }
    return state;
};

export default authReducer;
