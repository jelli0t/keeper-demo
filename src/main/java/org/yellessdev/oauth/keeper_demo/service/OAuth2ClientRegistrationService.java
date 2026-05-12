package org.yellessdev.oauth.keeper_demo.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientRequest;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientResponse;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
public class OAuth2ClientRegistrationService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder clientSecretEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public OAuth2ClientRegistrationService(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    public RegisterClientResponse register(RegisterClientRequest request) {
        if (registeredClientRepository.findByClientId(request.clientId()) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Client already exists: " + request.clientId());
        }

        Set<ClientAuthenticationMethod> authMethods = new LinkedHashSet<>();
        for (String raw : request.clientAuthenticationMethods()) {
            authMethods.add(parseClientAuthenticationMethod(raw));
        }

        Set<AuthorizationGrantType> grantTypes = new LinkedHashSet<>();
        for (String raw : request.authorizationGrantTypes()) {
            grantTypes.add(parseAuthorizationGrantType(raw));
        }

        if (grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            List<String> redirects = request.redirectUris() == null ? List.of() : request.redirectUris();
            if (redirects.isEmpty()) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "redirectUris is required when authorization_code grant is allowed");
            }
        }

        boolean confidential = authMethods.stream().anyMatch(m -> !ClientAuthenticationMethod.NONE.equals(m));
        String plainSecret = request.clientSecret();
        String generatedPlain = null;
        if (confidential) {
            if (plainSecret == null || plainSecret.isBlank()) {
                generatedPlain = randomSecret();
                plainSecret = generatedPlain;
            }
        } else if (plainSecret != null && !plainSecret.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "clientSecret must not be set when only the none authentication method is used");
        }

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.clientId().trim())
                .clientName(request.clientName() != null && !request.clientName().isBlank()
                        ? request.clientName().trim()
                        : request.clientId().trim());

        for (ClientAuthenticationMethod method : authMethods) {
            builder.clientAuthenticationMethod(method);
        }
        for (AuthorizationGrantType grantType : grantTypes) {
            builder.authorizationGrantType(grantType);
        }
        for (String scope : request.scopes()) {
            builder.scope(scope.trim());
        }
        if (request.redirectUris() != null) {
            for (String uri : request.redirectUris()) {
                if (uri != null && !uri.isBlank()) {
                    builder.redirectUri(uri.trim());
                }
            }
        }
        if (request.postLogoutRedirectUris() != null) {
            for (String uri : request.postLogoutRedirectUris()) {
                if (uri != null && !uri.isBlank()) {
                    builder.postLogoutRedirectUri(uri.trim());
                }
            }
        }

        if (confidential && plainSecret != null) {
            builder.clientSecret(clientSecretEncoder.encode(plainSecret));
        }

        builder.clientSettings(ClientSettings.builder().build());
        builder.tokenSettings(TokenSettings.builder().build());

        RegisteredClient saved = builder.build();
        registeredClientRepository.save(saved);

        return new RegisterClientResponse(
                saved.getId(),
                saved.getClientId(),
                saved.getClientName(),
                generatedPlain);
    }

    private static ClientAuthenticationMethod parseClientAuthenticationMethod(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Empty client authentication method");
        }
        String v = raw.trim().toLowerCase(Locale.ROOT);
        return switch (v) {
            case "none" -> ClientAuthenticationMethod.NONE;
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            default -> new ClientAuthenticationMethod(raw.trim());
        };
    }

    private static AuthorizationGrantType parseAuthorizationGrantType(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Empty authorization grant type");
        }
        String v = raw.trim().toLowerCase(Locale.ROOT);
        return switch (v) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "device_code" -> new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code");
            case "jwt_bearer" -> new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
            default -> new AuthorizationGrantType(raw.trim());
        };
    }

    private static String randomSecret() {
        byte[] bytes = new byte[24];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
