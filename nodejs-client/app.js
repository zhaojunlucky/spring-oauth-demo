const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const axios = require('axios');

// Add axios interceptors for debugging
axios.interceptors.request.use(request => {
  console.log('=== AXIOS REQUEST ===');
  console.log(`${request.method?.toUpperCase()} ${request.url}`);
  console.log('Headers:', request.headers);
  console.log('Data:', request.data);
  return request;
});

axios.interceptors.response.use(
  response => {
    console.log('=== AXIOS RESPONSE ===');
    console.log(`Status: ${response.status}`);
    console.log('Data:', response.data);
    return response;
  },
  error => {
    console.log('=== AXIOS ERROR ===');
    console.log('Error:', error.message);
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Data:', error.response.data);
    }
    return Promise.reject(error);
  }
);
const { AuthorizationCode } = require('simple-oauth2');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
const port = 3000;

// Debug helper function
const debug = (message, data = null) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[DEBUG] ${message}`);
    if (data) console.log(data);
  }
};

// Configure middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'oauth-client-secret',
  resave: false,
  saveUninitialized: true
}));

// Request logging middleware
app.use((req, res, next) => {
  debug(`${req.method} ${req.path}`, {
    query: req.query,
    body: req.body,
    sessionId: req.sessionID
  });
  next();
});

// Set up view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// OAuth2 configuration
const oauth2Config = {
  client: {
    id: 'nodejs-client',
    secret: 'client-secret'
  },
  auth: {
    tokenHost: 'http://localhost:8080',
    tokenPath: '/oauth2/token',
    authorizePath: '/oauth2/authorize'
  },
  options: {
    authorizationMethod: 'header',
    bodyFormat: 'form' // Use form format for request body
  }
};

// Create OAuth2 client
const oauth2Client = new AuthorizationCode(oauth2Config);

// Setup JWKS client for JWT verification
const jwks = jwksClient({
  jwksUri: 'http://localhost:8080/oauth2/jwks',
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5
});

// Function to get signing key for JWT verification
function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Function to verify JWT token
async function verifyToken(token) {
  return new Promise((resolve, reject) => {
    const options = {
      algorithms: ['RS256']
    };
    
    // First decode the token without verification to get the header
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      return reject(new Error('Invalid token'));
    }
    
    // Get the signing key
    getSigningKey(decoded.header, (err, signingKey) => {
      if (err) return reject(err);
      
      // Verify the token
      jwt.verify(token, signingKey, options, (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      });
    });
  });
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { 
    token: req.session.token || null,
    userData: req.session.userData || null,
    tokenInfo: req.session.tokenInfo || null
  });
});

// Start authorization flow
app.get('/authorize', (req, res) => {
  // Generate and store state for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  
  // Generate PKCE code challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  req.session.codeVerifier = codeVerifier;
  
  // Calculate code challenge
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  // Store PKCE and OAuth parameters in session
  req.session.pkceParams = {
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  };
  
  // Option 1: Redirect to Angular login app (current approach)
  const angularLoginUrl = `http://localhost:4200/login?client_id=${encodeURIComponent(oauth2Config.client.id)}`
    + `&redirect_uri=${encodeURIComponent('http://localhost:3000/callback')}`
    + `&response_type=code`
    + `&scope=${encodeURIComponent('openid read write')}`
    + `&state=${encodeURIComponent(state)}`
    + `&code_challenge=${encodeURIComponent(codeChallenge)}`
    + `&code_challenge_method=S256`;
  
  // Option 2: Use OAuth server's built-in authorization endpoint (for debugging)
  const oauthServerUrl = `http://localhost:8080/oauth2/authorize?client_id=${encodeURIComponent(oauth2Config.client.id)}`
    + `&redirect_uri=${encodeURIComponent('http://localhost:3000/callback')}`
    + `&response_type=code`
    + `&scope=${encodeURIComponent('openid read write')}`
    + `&state=${encodeURIComponent(state)}`
    + `&code_challenge=${encodeURIComponent(codeChallenge)}`
    + `&code_challenge_method=S256`;
  
  console.log('Angular login URL:', angularLoginUrl);
  console.log('OAuth server URL:', oauthServerUrl);
  console.log('Using OAuth server with Angular login integration...');
  res.redirect(oauthServerUrl); // OAuth server will redirect to Angular when auth needed
});

// Handle callback from Angular login app (not directly from the authorization server)
app.get('/callback', async (req, res) => {
  debugger; // Breakpoint here
  const { code, state } = req.query;
  
  console.log('=== CALLBACK DEBUG INFO ===');
  console.log('Callback received with state:', state);
  console.log('Session state:', req.session.oauthState);
  console.log('Full query params:', req.query);
  console.log('Session data:', {
    oauthState: req.session.oauthState,
    codeVerifier: req.session.codeVerifier,
    pkceParams: req.session.pkceParams
  });
  
  // Verify state to prevent CSRF attacks
  if (state !== req.session.oauthState) {
    return res.status(403).send('State mismatch, possible CSRF attack');
  }
  
  console.log('Received authorization code from Angular login app:', code);
  
  try {
    // Exchange authorization code for JWT access token
    console.log('=== STARTING JWT TOKEN EXCHANGE ===');
    console.log('Exchanging authorization code for access token...');
    console.log('Authorization code:', code);
    console.log('Code verifier:', req.session.codeVerifier);
    
    const tokenParams = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'http://localhost:3000/callback',
      client_id: oauth2Config.client.id,
      code_verifier: req.session.codeVerifier // PKCE
    };
    
    // Make token request to OAuth server
    const tokenResponse = await axios.post('http://localhost:8080/oauth2/token', 
      new URLSearchParams(tokenParams), 
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${oauth2Config.client.id}:${oauth2Config.client.secret}`).toString('base64')}`
        }
      }
    );
    
    const accessToken = tokenResponse.data;
    console.log('Received JWT access token:', accessToken);
    
    // Verify the JWT token
    const decodedToken = await verifyToken(accessToken.access_token);
    console.log('Decoded JWT token:', decodedToken);
    
    // Store the token in session
    req.session.token = accessToken;
    
    // Store user info from JWT claims
    req.session.userData = {
      username: decodedToken.sub || 'user', // Extract username from JWT subject
      roles: decodedToken.authorities || ['USER'], // Extract roles from JWT
      authenticated: true,
      tokenInfo: {
        issuer: decodedToken.iss,
        audience: decodedToken.aud,
        expiresAt: new Date(decodedToken.exp * 1000),
        issuedAt: new Date(decodedToken.iat * 1000),
        scopes: decodedToken.scope ? 
          (Array.isArray(decodedToken.scope) ? decodedToken.scope : decodedToken.scope.split(' ')) : []
      }
    };
    
    console.log('Successfully obtained and verified JWT access token');
    
    // Redirect to home page
    return res.redirect('/');
  } catch (error) {
    console.error('=== ERROR IN TOKEN EXCHANGE ===');
    console.error('Error handling callback:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
    console.error('Full error:', error);
    return res.status(500).send(`Error handling callback: ${error.message}. Please try again.`);
  }
});

// Get user data from resource server
app.get('/user-data', async (req, res) => {
  if (!req.session.token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    console.log('Fetching user data with token:', req.session.token.access_token.substring(0, 10) + '...');
    
    const response = await axios.get('http://localhost:8080/api/user', {
      headers: {
        'Authorization': `Bearer ${req.session.token.access_token}`
      }
    });
    
    console.log('User data response:', response.data);
    req.session.userData = response.data;
    res.redirect('/');
  } catch (error) {
    console.error('Error fetching user data:', error.message);
    console.error('Error details:', error.response ? error.response.data : 'No response data');
    res.status(500).json({ error: error.message });
  }
});

// Get public data (no auth required)
app.get('/public-data', async (req, res) => {
  try {
    console.log('Fetching public data');
    const response = await axios.get('http://localhost:8080/api/public');
    console.log('Public data response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching public data:', error.message);
    console.error('Error details:', error.response ? error.response.data : 'No response data');
    res.status(500).json({ error: error.message });
  }
});

// Refresh token route
app.get('/refresh-token', async (req, res) => {
  if (!req.session.token || !req.session.token.refresh_token) {
    return res.status(401).json({ error: 'No refresh token available' });
  }
  
  try {
    const accessToken = oauth2Client.createToken(req.session.token);
    const refreshedToken = await accessToken.refresh();
    req.session.token = refreshedToken.token;
    
    console.log('Token refreshed:', JSON.stringify({
      access_token: refreshedToken.token.access_token ? refreshedToken.token.access_token.substring(0, 10) + '...' : 'undefined',
      token_type: refreshedToken.token.token_type,
      expires_at: refreshedToken.token.expires_at,
      refresh_token: refreshedToken.token.refresh_token ? 'present' : 'undefined'
    }));
    
    // Decode the new JWT token
    try {
      const decoded = await verifyToken(refreshedToken.token.access_token);
      req.session.tokenInfo = decoded;
    } catch (tokenError) {
      console.error('Token verification error:', tokenError.message);
    }
    
    res.redirect('/');
  } catch (error) {
    console.error('Error refreshing token:', error.message);
    console.error('Error details:', error.response ? error.response.data : 'No response data');
    res.status(500).json({ error: error.message });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(port, () => {
  console.log(`OAuth client app listening at http://localhost:${port}`);
});
