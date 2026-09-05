import {UUID} from "node:crypto";

export interface SignUpRequestDTO {
    email: string,
    password: string,
    fullName: string,
    captchaToken: string,
}

export interface UpdateUserRequestDTO {
    email?: string,
    password?: string,
    fullName: string,
}

export interface LoginResponseDTO {
    token: string | null,
    isAuthenticated: boolean,
    lockoutTimeRemainingMinutes?: number | null,
}

export interface LoginRequestDTO {
    email: string,
    password: string,
}

export interface UserDTO {
    id: UUID,
    email: string,
    fullName: string,
}

export interface AuthenticationErrorDTO {
    details: string,
    message: string,
}

export interface ApiResponseDTO {
    message: string,
    status: boolean,
}

export interface PasswordChangeRequestDTO {
    oldPassword: string;
    newPassword: string;
}

export interface VerifyOtpRequestDTO {
    email: string,
    otpCode: string,
}

export interface PasswordResetOtpRequestDTO {
    email: string,
    captchaToken: string,
}

export interface ResetPasswordWithOtpRequestDTO {
    email: string,
    otpCode: string,
    newPassword: string,
}

export type AuthReducerState = {
    signin: LoginResponseDTO | null,
    signup: ApiResponseDTO | null,
    reqUser: UserDTO | null,
    searchUser: UserDTO[] | null,
updateUser: ApiResponseDTO | null,
    passwordChanged: ApiResponseDTO | null,
    pendingEmail: string | null,
    otpVerification: LoginResponseDTO | null,
    passwordResetOtpRequest: ApiResponseDTO | null,
    passwordReset: LoginResponseDTO | null,
}
