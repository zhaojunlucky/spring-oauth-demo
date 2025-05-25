export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  message?: string;
  code?: string;
  error?: string;
}

export interface OAuthParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state: string;
  [key: string]: string;
}

export interface OAuthValidationResponse {
  valid: boolean;
  error?: string;
  error_description?: string;
}
