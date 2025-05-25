import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, catchError, map, of } from 'rxjs';
import { LoginRequest, LoginResponse, OAuthParams, OAuthValidationResponse } from '../models/auth.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8080'; // Spring Boot OAuth server URL

  constructor(private http: HttpClient) { }

  /**
   * Authenticate user with username and password
   * @param loginRequest The login credentials
   * @returns Observable with login response
   */
  login(loginRequest: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/api/auth/login`, loginRequest)
      .pipe(
        map(response => response),
        catchError(error => {
          console.error('Login error:', error);
          return of({
            success: false,
            message: error.error?.message || 'Authentication failed. Please try again.',
            error: error.status
          });
        })
      );
  }

  /**
   * Parse OAuth parameters from URL query string
   * @returns OAuth parameters object
   */
  getOAuthParams(): OAuthParams {
    const queryParams = new URLSearchParams(window.location.search);
    const params: OAuthParams = {
      client_id: queryParams.get('client_id') || '',
      redirect_uri: queryParams.get('redirect_uri') || '',
      response_type: queryParams.get('response_type') || 'code',
      scope: queryParams.get('scope') || '',
      state: queryParams.get('state') || ''
    };

    // Add any additional parameters that might be present
    queryParams.forEach((value, key) => {
      if (!params[key]) {
        params[key] = value;
      }
    });

    return params;
  }
  
  /**
   * Validate OAuth parameters with the backend
   * @param params OAuth parameters to validate
   * @returns Observable with validation result
   */
  validateOAuthParams(params: OAuthParams): Observable<OAuthValidationResponse> {
    // Create HTTP parameters from OAuth parameters
    let httpParams = new HttpParams()
      .set('client_id', params.client_id)
      .set('redirect_uri', params.redirect_uri)
      .set('response_type', params.response_type);
    
    if (params.scope) {
      httpParams = httpParams.set('scope', params.scope);
    }
    
    return this.http.get<OAuthValidationResponse>(`${this.apiUrl}/api/auth/validate-oauth-params`, { params: httpParams })
      .pipe(
        catchError(error => {
          console.error('OAuth validation error:', error);
          return of({
            valid: false,
            error: error.error?.error || 'invalid_request',
            error_description: error.error?.error_description || 'Failed to validate OAuth parameters'
          });
        })
      );
  }

  /**
   * Redirect back to OAuth client with authorization code or error
   * @param success Whether authentication was successful
   * @param code Optional authorization code
   * @param error Optional error message
   */
  redirectToClient(success: boolean, code?: string, error?: string): void {
    const params = this.getOAuthParams();
    let redirectUrl = params.redirect_uri;

    if (success && code) {
      // Successful authentication
      redirectUrl += `?code=${encodeURIComponent(code)}`;
      if (params.state) {
        redirectUrl += `&state=${encodeURIComponent(params.state)}`;
      }
    } else {
      // Authentication failed
      redirectUrl += `?error=${encodeURIComponent(error || 'access_denied')}`;
      redirectUrl += `&error_description=${encodeURIComponent('Authentication failed')}`;
      if (params.state) {
        redirectUrl += `&state=${encodeURIComponent(params.state)}`;
      }
    }

    // Redirect to OAuth client
    window.location.href = redirectUrl;
  }
}
