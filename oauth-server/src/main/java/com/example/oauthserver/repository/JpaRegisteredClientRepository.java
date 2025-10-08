package com.example.oauthserver.repository;

import com.example.oauthserver.entity.Client;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

// @Component - Disabled to avoid bean conflicts with in-memory repository
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final ObjectMapper objectMapper;

    public JpaRegisteredClientRepository(ClientRepository clientRepository, ObjectMapper objectMapper) {
        this.clientRepository = clientRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Client client = toEntity(registeredClient);
        clientRepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toObject)
                .orElse(null);
    }

    private Client toEntity(RegisteredClient registeredClient) {
        Client client = new Client();
        client.setId(registeredClient.getId());
        client.setClientId(registeredClient.getClientId());
        client.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        client.setClientName(registeredClient.getClientName());
        
        // Convert Set<ClientAuthenticationMethod> to String
        client.setClientAuthenticationMethods(
                writeValueAsString(registeredClient.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .toList()));
        
        // Convert Set<AuthorizationGrantType> to String
        client.setAuthorizationGrantTypes(
                writeValueAsString(registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .toList()));
        
        // Convert Set<String> to String
        client.setRedirectUris(writeValueAsString(new ArrayList<>(registeredClient.getRedirectUris())));
        client.setScopes(writeValueAsString(new ArrayList<>(registeredClient.getScopes())));
        
        // Convert ClientSettings to String
        client.setClientSettings(writeValueAsString(registeredClient.getClientSettings().getSettings()));
        
        // Convert TokenSettings to String
        client.setTokenSettings(writeValueAsString(registeredClient.getTokenSettings().getSettings()));
        
        return client;
    }

    private RegisteredClient toObject(Client client) {
        Set<String> clientAuthenticationMethods = readValue(client.getClientAuthenticationMethods(), new TypeReference<Set<String>>() {});
        Set<String> authorizationGrantTypes = readValue(client.getAuthorizationGrantTypes(), new TypeReference<Set<String>>() {});
        Set<String> redirectUris = readValue(client.getRedirectUris(), new TypeReference<Set<String>>() {});
        Set<String> scopes = readValue(client.getScopes(), new TypeReference<Set<String>>() {});
        Map<String, Object> clientSettingsMap = readValue(client.getClientSettings(), new TypeReference<Map<String, Object>>() {});
        Map<String, Object> tokenSettingsMap = readValue(client.getTokenSettings(), new TypeReference<Map<String, Object>>() {});

        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName());

        // Add client authentication methods
        clientAuthenticationMethods.forEach(method ->
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method)));

        // Add authorization grant types
        authorizationGrantTypes.forEach(grantType ->
                builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

        // Add redirect URIs
        redirectUris.forEach(builder::redirectUri);

        // Add scopes
        scopes.forEach(builder::scope);

        // Add client settings
        builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

        // Add token settings
        builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

        return builder.build();
    }

    private String writeValueAsString(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private <T> T readValue(String value, TypeReference<T> typeReference) {
        try {
            return StringUtils.hasText(value) ?
                    objectMapper.readValue(value, typeReference) : null;
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
}
