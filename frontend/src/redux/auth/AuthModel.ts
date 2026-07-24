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
    token: string,
    isAuthenticated: boolean,
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

export interface VerifyOtpRequestDTO {
    email: string,
    otpCode: string,
}

export type AuthReducerState = {
    signin: LoginResponseDTO | null,
    signup: ApiResponseDTO | null,
    reqUser: UserDTO | null,
    searchUser: UserDTO[] | null,
    updateUser: ApiResponseDTO | null,
    pendingEmail: string | null,
    otpVerification: LoginResponseDTO | null,
}