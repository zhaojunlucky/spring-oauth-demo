package com.example.oauthserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/user")
    public Map<String, Object> user() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("name", auth.getName());
        userInfo.put("authorities", auth.getAuthorities());
        
        if (auth instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
            userInfo.put("token_attributes", jwtAuth.getToken().getClaims());
        }
        
        return userInfo;
    }

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a public endpoint");
        return response;
    }
}
