# Angular OAuth Client

A Node.js OAuth 2.0 client that integrates with a Spring Boot Authorization Server and an Angular login form.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Token refresh handling
- User session management
- Protected routes
- User profile display
- API request handling with token injection
- Error handling and logging

## Prerequisites

- Node.js 14.x or later
- npm or yarn
- A running Spring Boot OAuth2 Authorization Server
- Angular application with login form

## Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=3000
NODE_ENV=development
SESSION_SECRET=your-session-secret

# OAuth2 Configuration
AUTH_SERVER_URL=http://localhost:8080
CLIENT_ID=angular-client
CLIENT_SECRET=secret
REDIRECT_URI=http://localhost:3000/auth/callback
SCOPE=read write

# Angular App Configuration
ANGULAR_APP_URL=http://localhost:4200

# Endpoints (usually these defaults work)
TOKEN_ENDPOINT=/oauth2/token
AUTHORIZATION_ENDPOINT=/oauth2/authorize
USER_INFO_ENDPOINT=/user/me
JWKS_URI=/oauth2/jwks
```

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```
3. Configure your environment variables in `.env`
4. Start the server:
   ```bash
   npm start
   # or for development with auto-reload
   npm run dev
   ```

## Usage

1. Access the application at `http://localhost:3000`
2. Click the "Login" button to be redirected to the Angular login form
3. After successful authentication, you'll be redirected back to the home page with your user information
4. Use the "Get User Info" button to make an authenticated API request
5. Click "Logout" to end your session

## Project Structure

- `app.js` - Main application file
- `views/` - EJS templates
  - `index.ejs` - Main application view
  - `error.ejs` - Error page
  - `partials/` - Reusable template partials
    - `header.ejs` - Navigation header
- `.env` - Environment configuration (create this file)
- `package.json` - Project dependencies and scripts

## Security Considerations

- Always use HTTPS in production
- Keep your `SESSION_SECRET` secure and never commit it to version control
- Configure appropriate CORS settings for your environment
- Use secure cookies in production
- Implement proper CSRF protection

## License

MIT
