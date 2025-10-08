import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormGroup, FormBuilder, Validators } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';

import { AuthService } from '../../services/auth.service';
import { LoginRequest, OAuthParams } from '../../models/auth.model';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatProgressSpinnerModule,
    MatSnackBarModule
  ],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  loginForm!: FormGroup;
  isLoading = false;
  oauthParams!: OAuthParams;
  errorMessage = '';

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    // Initialize the login form
    this.loginForm = this.formBuilder.group({
      username: ['user', [Validators.required]],
      password: ['password', [Validators.required]]
    });

    // Get OAuth parameters from URL
    this.oauthParams = this.authService.getOAuthParams();

    // First do basic client-side validation
    if (!this.oauthParams.client_id || !this.oauthParams.redirect_uri) {
      this.errorMessage = 'Invalid OAuth request. Missing required parameters.';
      return;
    }

    // Then validate with the backend
    this.isLoading = true;
    this.authService.validateOAuthParams(this.oauthParams).subscribe({
      next: (response) => {
        this.isLoading = false;
        if (!response.valid) {
          this.errorMessage = response.error_description || 'Invalid OAuth parameters';
          // Optionally redirect back to client with error
          // this.authService.redirectToClient(false, undefined, response.error || 'invalid_request');
        }
      },
      error: (error) => {
        this.isLoading = false;
        this.errorMessage = 'Failed to validate OAuth parameters';
        console.error('OAuth validation error:', error);
      }
    });
  }

  onSubmit(): void {
    if (this.loginForm.invalid) {
      // Mark all fields as touched to trigger validation messages
      Object.keys(this.loginForm.controls).forEach(key => {
        const control = this.loginForm.get(key);
        control?.markAsTouched();
      });
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    const loginRequest: LoginRequest = {
      username: this.loginForm.value.username,
      password: this.loginForm.value.password
    };

    this.authService.login(loginRequest).subscribe({
      next: (response) => {
        this.isLoading = false;

        if (response.success) {
          // Successful login, now redirect to OAuth2 authorize endpoint
          // Add a small delay to ensure session is properly established
          setTimeout(() => {
            this.redirectToOAuth2Authorize();
          }, 100);
        } else {
          // Login failed
          this.errorMessage = response.message || 'Authentication failed';
          this.snackBar.open(this.errorMessage, 'Close', {
            duration: 5000,
            horizontalPosition: 'center',
            verticalPosition: 'bottom'
          });
        }
      },
      error: (error) => {
        this.isLoading = false;
        this.errorMessage = 'An error occurred during login. Please try again.';
        this.snackBar.open(this.errorMessage, 'Close', {
          duration: 5000,
          horizontalPosition: 'center',
          verticalPosition: 'bottom'
        });
        console.error('Login error:', error);
      }
    });
  }

  // Helper method to check if a field is invalid and touched
  isFieldInvalid(fieldName: string): boolean {
    const control = this.loginForm.get(fieldName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }

  // Cancel login and redirect back to client with error
  cancelLogin(): void {
    this.authService.redirectToClient(false, undefined, 'user_cancelled');
  }

  // Redirect to Spring OAuth2 authorize endpoint after successful authentication
  private redirectToOAuth2Authorize(): void {
    // Build the OAuth2 authorize URL with the original parameters
    const baseUrl = 'http://localhost:8080/oauth2/authorize';
    const params = new URLSearchParams({
      client_id: this.oauthParams.client_id,
      redirect_uri: this.oauthParams.redirect_uri,
      response_type: this.oauthParams.response_type || 'code',
      scope: this.oauthParams.scope || 'openid read write',
      state: this.oauthParams.state || '',
      code_challenge: this.oauthParams['code_challenge'] || '',
      code_challenge_method: this.oauthParams['code_challenge_method'] || 'S256'
    });

    const authorizeUrl = `${baseUrl}?${params.toString()}`;
    
    console.log('Redirecting to OAuth2 authorize endpoint:', authorizeUrl);
    
    // Redirect to Spring's OAuth2 authorize endpoint
    // Since the user is already authenticated in this session,
    // Spring should generate the authorization code and redirect back
    window.location.href = authorizeUrl;
  }
}
