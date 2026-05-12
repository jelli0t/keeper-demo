package org.yellessdev.oauth.keeper_demo.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.UUID;

@Configuration
public class OAuth2PersistenceConfig {

    /**
     * Registered OAuth2 clients ({@code oauth2_registered_client} table, Flyway V2).
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * Authorization codes and tokens ({@code oauth2_authorization} table, Flyway V2).
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    /**
     * Initial demo client when the table is empty (aligned with former YAML registration).
     * Add or update clients via SQL or admin tooling against {@code oauth2_registered_client}.
     */
    @Bean
    ApplicationRunner seedRegisteredClientIfAbsent(RegisteredClientRepository registeredClientRepository) {
        return args -> {
            if (registeredClientRepository.findByClientId("plane-client-id") != null) {
                return;
            }
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("plane-client-id")
                    .clientSecret("{bcrypt}$2y$10$xAjCtV3oAjwz6wP/jVhXse1X3frp4TLbpSYIUoVArmcNd.gW9A5Ji")
                    .clientName("Plane client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .redirectUri("http://localhost:8080/login/oauth2/code/plane-client-id")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope(OidcScopes.EMAIL)
                    .clientSettings(ClientSettings.builder().build())
                    .tokenSettings(TokenSettings.builder().build())
                    .build();
            registeredClientRepository.save(client);
        };
    }
}
