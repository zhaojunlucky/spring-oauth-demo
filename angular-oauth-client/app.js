require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { AuthorizationCode } = require('simple-oauth2');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  authServerUrl: process.env.AUTH_SERVER_URL || 'http://test.magicworldz.de:8080',
  clientId: process.env.CLIENT_ID || 'nodejs-client',
  clientSecret: process.env.CLIENT_SECRET || 'client-secret',
  redirectUri: process.env.REDIRECT_URI || 'http://test.magicworldz.de:3000/auth/callback',
  scope: process.env.SCOPE || 'read write',
  angularAppUrl: process.env.ANGULAR_APP_URL || 'http://test.magicworldz.de:4200',
  sessionSecret: process.env.SESSION_SECRET || 'your-session-secret',
  tokenEndpoint: process.env.TOKEN_ENDPOINT || 'http://test.magicworldz.de:8080/api/oauth2/token',
  authorizationEndpoint: process.env.AUTHORIZATION_ENDPOINT || 'http://test.magicworldz.de:8080/api/oauth2/authorize',
  userInfoEndpoint: process.env.USER_INFO_ENDPOINT || 'http://test.magicworldz.de:8080/api/users/me',
  jwksUri: process.env.JWKS_URI || 'http://test.magicworldz.de:8080/api/oauth2/jwks'
};

// Configure OAuth2 client
const oauth2Client = new AuthorizationCode({
  client: {
    id: config.clientId,
    secret: config.clientSecret,
  },
  auth: {
    tokenHost: config.authServerUrl,
    tokenPath: '/api/oauth2/token',
    authorizePath: '/api/oauth2/authorize',
  },
  options: {
    authorizationMethod: 'body'
  }
});

// Configure JWT verification client
const jwksClientInstance = jwksClient({
  jwksUri: config.jwksUri,
  timeout: 30000, // 30 seconds
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5
});

// Middleware
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Helper function to verify JWT token
async function verifyToken(token) {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw new Error('Invalid token');
    }

    const key = await jwksClientInstance.getSigningKey(decoded.header.kid);
    const signingKey = key.getPublicKey();

    return jwt.verify(token, signingKey, {
      algorithms: ['RS256']
    });
  } catch (error) {
    console.error('Token verification failed:', error);
    throw error;
  }
}

// Middleware to check if user is authenticated
async function isAuthenticated(req, res, next) {
  try {
    if (req.session.token) {
      // Check if token is expired
      const token = await oauth2Client.createToken(req.session.token);
      
      if (token.expired()) {
        // Try to refresh token
        try {
          const newToken = await token.refresh();
          req.session.token = newToken.token;
          return next();
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError);
          return res.redirect('/login');
        }
      }
      return next();
    }
    res.redirect('/login');
  } catch (error) {
    console.error('Authentication error:', error);
    res.redirect('/login');
  }
}

// Routes
app.get('/', isAuthenticated, async (req, res) => {
  try {
    // First, get CSRF token from /api/auth/csrf
    const csrfResponse = await axios.get(`${config.authServerUrl}/api/auth/csrf`, {
      headers: {
        'Authorization': `Bearer ${req.session.token.access_token}`
      }
    });
    
    // Extract CSRF token from cookie
    const cookies = csrfResponse.headers['set-cookie'];
    let csrfToken = null;
    let cookieHeader = '';
    
    if (cookies) {
      const csrfCookie = cookies.find(cookie => cookie.startsWith('XSRF-TOKEN='));
      if (csrfCookie) {
        csrfToken = csrfCookie.split(';')[0].split('=')[1];
      }
      // Build cookie header from all cookies
      cookieHeader = cookies.map(cookie => cookie.split(';')[0]).join('; ');
    }
    
    console.log('CSRF Token received:', csrfToken);
    console.log('Cookies to send:', cookieHeader);
    
    // Now make the GET request to /api/users/me with CSRF token and Bearer token
    const userInfo = await axios.get(config.userInfoEndpoint, {
      headers: {
        'Authorization': `Bearer ${req.session.token.access_token}`,
        'X-XSRF-TOKEN': csrfToken,
        'Cookie': cookieHeader
      }
    });
    
    res.render('index', {
      user: userInfo.data,
      token: req.session.token
    });
  } catch (error) {
    console.error('Error fetching user info:', error);
    console.error('Error response:', error.response?.data);
    
    // Fallback: decode JWT token to get user info
    try {
      const decoded = jwt.decode(req.session.token.access_token);
      const userInfo = {
        username: decoded.sub,
        scopes: decoded.scope,
        issuer: decoded.iss,
        audience: decoded.aud,
        expiresAt: new Date(decoded.exp * 1000).toISOString(),
        issuedAt: new Date(decoded.iat * 1000).toISOString()
      };
      
      res.render('index', {
        user: userInfo,
        token: req.session.token
      });
    } catch (fallbackError) {
      console.error('Fallback error:', fallbackError);
      res.redirect('/login');
    }
  }
});

// Login route - redirects to Angular login page
app.get('/login', (req, res) => {
  // Store the original URL to redirect back after login
  if (req.query.redirectTo) {
    req.session.returnTo = req.query.redirectTo;
  }
  
  // Redirect to Angular app login page with OAuth parameters
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    response_type: 'code',
    auth_endpoint: config.authorizationEndpoint
  });
  
  const angularLoginUrl = `${config.angularAppUrl}/auth/login?${params.toString()}`;
  res.redirect(angularLoginUrl);
});

// OAuth callback route
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    
    console.log('Callback received with code:', code);
    console.log('State:', state);
    
    if (!code) {
      throw new Error('Authorization code is required');
    }
    
    const tokenParams = {
      code,
      redirect_uri: config.redirectUri,
      scope: config.scope,
    };
    
    console.log('Token request params:', tokenParams);
    console.log('Token endpoint:', config.tokenEndpoint);
    
    const accessToken = await oauth2Client.getToken(tokenParams);
    
    console.log('Token received successfully');
    
    // Verify the ID token if present
    if (accessToken.token.id_token) {
      await verifyToken(accessToken.token.id_token);
    }
    
    // Store the token in the session
    req.session.token = accessToken.token;
    req.session.save();
    
    // Redirect to the original URL or home page
    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    
    res.redirect(redirectTo);
  } catch (error) {
    console.error('Authentication error:', error.message);
    
    // Log error details safely
    if (error.data) {
      console.error('Error status:', error.data.res?.statusCode);
      console.error('Error payload:', error.data.payload);
      console.error('Error headers:', error.data.headers);
    }
    
    // Check if it's an OAuth2 server error
    const serverError = error.data?.payload;
    const errorMessage = serverError 
      ? `OAuth2 Server Error: ${serverError.error} - ${serverError.status} (${serverError.path})`
      : error.message;
    
    res.status(500).render('error', {
      message: 'Authentication failed',
      error: errorMessage
    });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  // Clear the session
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    // Redirect to the Angular app's logout endpoint
    res.redirect(`${config.angularAppUrl}/logout`);
  });
});

// API proxy to forward requests to the auth server
app.use('/api', createProxyMiddleware({
  target: config.authServerUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api': ''
  },
  onProxyReq: (proxyReq, req, res) => {
    // Add authorization header if user is authenticated
    if (req.session && req.session.token) {
      proxyReq.setHeader('Authorization', `Bearer ${req.session.token.access_token}`);
    }
  },
  onError: (err, req, res) => {
    console.error('Proxy error:', err);
    res.status(500).json({ error: 'Proxy error' });
  }
}));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).render('error', {
    message: 'Something went wrong',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://test.magicworldz.de:${PORT}`);
  console.log(`OAuth2 Authorization Endpoint: ${config.authorizationEndpoint}`);
  console.log(`OAuth2 Token Endpoint: ${config.tokenEndpoint}`);
  console.log(`Angular App: ${config.angularAppUrl}`);
});

module.exports = app;
