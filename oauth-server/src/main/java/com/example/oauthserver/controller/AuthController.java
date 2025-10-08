package com.example.oauthserver.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:4200", "http://localhost:3000"})
public class AuthController {

    @Autowired
    private UserDetailsService userDetailsService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    /**
     * Login endpoint for the Angular login app
     * This endpoint validates credentials and establishes authentication in Spring Security context
     * @param loginRequest The login credentials
     * @param request HTTP request to access session
     * @return ResponseEntity with login result
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        try {
            // Validate username and password
            UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
            
            if (!passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
                throw new BadCredentialsException("Invalid username or password");
            }
            
            // Create authentication token and set in security context
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Store authentication in session so OAuth2 authorize endpoint can access it
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            
            // Authentication successful
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Authentication successful");
            
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Invalid username or password");
            
            return ResponseEntity.status(401).body(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "An error occurred during login");
            
            return ResponseEntity.status(500).body(response);
        }
    }
    
    
    /**
     * Validate OAuth parameters
     * @param clientId The client ID
     * @param redirectUri The redirect URI
     * @param responseType The response type
     * @return ResponseEntity with validation result
     */
    @GetMapping("/validate-oauth-params")
    public ResponseEntity<?> validateOAuthParams(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType) {
        
        Map<String, Object> response = new HashMap<>();
        
        // TODO: In a production environment, you would validate against registered clients in a database
        // For this demo, we'll use a simple validation
        boolean isValid = isValidClientId(clientId) && isValidRedirectUri(clientId, redirectUri);
        
        if (isValid) {
            response.put("valid", true);
            return ResponseEntity.ok(response);
        } else {
            response.put("valid", false);
            response.put("error", "invalid_request");
            response.put("error_description", "Invalid client_id or redirect_uri");
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    /**
     * Validate client ID against registered clients
     * @param clientId The client ID to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidClientId(String clientId) {
        // In a real application, this would check against a database of registered clients
        // For demo purposes, we'll accept any non-empty client ID
        return clientId != null && !clientId.trim().isEmpty();
        // Uncomment for stricter validation with specific client IDs
        // return "client1".equals(clientId) || "client2".equals(clientId) || "angular-client".equals(clientId);
    }
    
    /**
     * Validate redirect URI for a given client ID
     * @param clientId The client ID
     * @param redirectUri The redirect URI to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidRedirectUri(String clientId, String redirectUri) {
        // In a real application, this would check against registered redirect URIs for the client
        // For demo/development purposes, we'll accept any localhost URI
        if (redirectUri != null && (redirectUri.startsWith("http://localhost:") || 
                                   redirectUri.startsWith("https://localhost:"))) {
            return true;
        }
        
        // For production, uncomment and use a strict validation approach like this:
        /*
        Map<String, String[]> validRedirectUris = new HashMap<>();
        validRedirectUris.put("client1", new String[] {"http://localhost:3000/callback"});
        validRedirectUris.put("client2", new String[] {"http://localhost:8080/callback"});
        validRedirectUris.put("angular-client", new String[] {"http://localhost:4200/callback"});
        
        String[] allowedUris = validRedirectUris.getOrDefault(clientId, new String[0]);
        for (String uri : allowedUris) {
            if (redirectUri.startsWith(uri)) {
                return true;
            }
        }
        */
        
        return false;
    }
    
    /**
     * Login request model
     */
    public static class LoginRequest {
        private String username;
        private String password;
        
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
        
        public String getPassword() {
            return password;
        }
        
        public void setPassword(String password) {
            this.password = password;
        }
    }
}
