import {
    ApiResponseDTO, AuthenticationErrorDTO,
    LoginRequestDTO,
    LoginResponseDTO,
    PasswordChangeRequestDTO,
    PasswordResetOtpRequestDTO,
    ResetPasswordWithOtpRequestDTO,
    SignUpRequestDTO,
    UpdateUserRequestDTO,
    UserDTO,
    VerifyOtpRequestDTO
} from "./AuthModel";
import * as actionTypes from './AuthActionType';
import {BASE_API_URL, TOKEN} from "../../config/Config";
import {AUTHORIZATION_PREFIX} from "../Constants";
import {AppDispatch} from "../Store";
import Logger from "../../services/Logger";

const AUTH_PATH = 'auth';
const USER_PATH = 'api/users';

export const register = (data: SignUpRequestDTO) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${AUTH_PATH}/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

const resData: ApiResponseDTO = await res.json();
        Logger.info('Signup OTP requested', resData);
        dispatch({type: actionTypes.REGISTER, payload: resData});
    } catch (error: any) {
        Logger.error('Register failed', error);
    }
};

export const verifyOtp = (data: VerifyOtpRequestDTO) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${AUTH_PATH}/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

const resData: LoginResponseDTO = await res.json();
        if (resData.token) {
            localStorage.setItem(TOKEN, resData.token);
        }
        Logger.info('OTP verified, user created', resData);
        dispatch({type: actionTypes.VERIFY_OTP, payload: resData});
    } catch (error: any) {
        Logger.error('OTP verification failed', error);
    }
};

export const loginUser = (data: LoginRequestDTO) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${AUTH_PATH}/signin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const resData: LoginResponseDTO = await res.json();
        if (resData.token) {
            localStorage.setItem(TOKEN, resData.token);
        }
        Logger.info('User logged in', { hasToken: !!resData.token, isAuthenticated: resData.isAuthenticated });
        dispatch({type: actionTypes.LOGIN_USER, payload: resData});
    } catch (error: any) {
        Logger.error('Login failed', error);
    }
};

export const requestPasswordResetOtp = (data: PasswordResetOtpRequestDTO) => async (dispatch: AppDispatch): Promise<ApiResponseDTO> => {
    const res: Response = await fetch(`${BASE_API_URL}/${AUTH_PATH}/forgot-password/request-otp`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const resData: ApiResponseDTO = await res.json();
    if (!res.ok) {
        throw new Error((resData as any).message || "Unable to request a reset code.");
    }
    Logger.info('Password reset OTP requested', { email: data.email });
    dispatch({type: actionTypes.REQUEST_PASSWORD_RESET_OTP, payload: resData});
    return resData;
};

export const resetPasswordWithOtp = (data: ResetPasswordWithOtpRequestDTO) => async (dispatch: AppDispatch): Promise<LoginResponseDTO> => {
    const res: Response = await fetch(`${BASE_API_URL}/${AUTH_PATH}/forgot-password/verify-otp`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const resData: LoginResponseDTO = await res.json();
    if (!res.ok) {
        throw new Error((resData as any).message || "Password reset failed.");
    }
    if (resData.token) {
        localStorage.setItem(TOKEN, resData.token);
    }
    Logger.info('Password reset OTP verified', { hasToken: !!resData.token, isAuthenticated: resData.isAuthenticated });
    dispatch({type: actionTypes.RESET_PASSWORD_WITH_OTP, payload: resData});
    return resData;
};

export const currentUser = (token: string) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${USER_PATH}/profile`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
        });

        const resData: UserDTO | AuthenticationErrorDTO = await res.json();
        if ('message' in resData && resData.message === 'Authentication Error') {
            localStorage.removeItem(TOKEN);
            Logger.info('Removed invalid token from local storage');
            return;
        }
        Logger.info('Fetched current user', { userId: (resData as UserDTO).id });
        dispatch({type: actionTypes.REQ_USER, payload: resData});
    } catch (error: any) {
        Logger.error('Fetching current user failed', error);
    }
};

export const searchUser = (data: string, token: string) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res: Response = await fetch(`${BASE_API_URL}/${USER_PATH}/search?name=${data}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            }
        });

        const resData: UserDTO[] = await res.json();
        Logger.info('Searched user data', { count: resData.length });
        dispatch({type: actionTypes.SEARCH_USER, payload: resData});
    } catch (error: any) {
        Logger.error('Searching user failed', error);
    }
};

export const updateUser = (data: UpdateUserRequestDTO, token: string) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res = await fetch(`${BASE_API_URL}/${USER_PATH}/update`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
            body: JSON.stringify(data),
        });

        const resData: ApiResponseDTO = await res.json();
        Logger.info('User updated', { fullName: data.fullName });
        dispatch({type: actionTypes.UPDATE_USER, payload: resData});
    } catch (error: any) {
        Logger.error('User update failed', error);
    }
};

export const changePassword = (data: PasswordChangeRequestDTO, token: string) => async (dispatch: AppDispatch): Promise<void> => {
    try {
        const res = await fetch(`${BASE_API_URL}/${AUTH_PATH}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
            body: JSON.stringify(data),
        });

        const resData: ApiResponseDTO = await res.json();
        Logger.info('Password changed');
        dispatch({type: actionTypes.CHANGE_PASSWORD, payload: resData});
    } catch (error: any) {
        Logger.error('Password change failed', error);
    }
};

export const logoutUser = () => async (dispatch: AppDispatch): Promise<void> => {
    localStorage.removeItem(TOKEN);
    dispatch({type: actionTypes.LOGOUT_USER, payload: null});
    dispatch({type: actionTypes.REQ_USER, payload: null});
    Logger.info('User logged out');
};

