package org.yellessdev.oauth.keeper_demo.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.QueryParameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Documents REST controllers via SpringDoc and adds OpenAPI paths for Spring Authorization Server
 * endpoints (they are not Spring MVC controllers, so they are registered manually).
 */
@Configuration
public class OpenApiConfig {

    public static final String TAG_AUTHORIZATION_SERVER = "OAuth2 Authorization Server";

    private static final String OAUTH2_AUTH_CODE_SCHEME = "oauth2AuthorizationCode";

    @Bean
    public OpenAPI keeperDemoOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("keeper-demo")
                        .version("0.0.1")
                        .description("""
                                Application REST API and OAuth 2.0 / OpenID Connect 1.0 endpoints served by \
                                Spring Authorization Server. Metadata and browser flows use this same origin; \
                                use relative URLs in clients where possible.
                                """))
                .addServersItem(new Server().url("/").description("This application"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes(
                                "bearerJwt",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("OAuth 2.0 access token (RFC 6750)")
                        )
                        .addSecuritySchemes(
                                OAUTH2_AUTH_CODE_SCHEME,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.OAUTH2)
                                        .description("Authorization code (+ refresh) against this server")
                                        .flows(new OAuthFlows()
                                                .authorizationCode(new OAuthFlow()
                                                        .authorizationUrl("/oauth2/authorize")
                                                        .tokenUrl("/oauth2/token")
                                                        .refreshUrl("/oauth2/token")
                                                        .scopes(new Scopes()
                                                                .addString("openid", "OpenID Connect")
                                                                .addString("profile", "Profile scope")
                                                                .addString("email", "Email scope")))
                                        )
                        ));
    }

    @Bean
    public OpenApiCustomizer authorizationServerEndpointsCustomizer() {
        return openApi -> {
            Paths paths = openApi.getPaths();
            if (paths == null) {
                paths = new Paths();
                openApi.setPaths(paths);
            }
            putIfAbsent(paths, "/.well-known/openid-configuration", openIdConfigurationPathItem());
            putIfAbsent(paths, "/.well-known/oauth-authorization-server", oauthAuthorizationServerMetadataPathItem());
            putIfAbsent(paths, "/oauth2/authorize", oauth2AuthorizePathItem());
            putIfAbsent(paths, "/oauth2/token", oauth2TokenPathItem());
            putIfAbsent(paths, "/oauth2/jwks", oauth2JwksPathItem());
            putIfAbsent(paths, "/userinfo", userInfoPathItem());
        };
    }

    private static void putIfAbsent(Paths paths, String path, PathItem item) {
        if (!paths.containsKey(path)) {
            paths.addPathItem(path, item);
        }
    }

    private static PathItem openIdConfigurationPathItem() {
        return new PathItem().get(new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("OpenID Provider configuration")
                .description("OIDC discovery document (RFC 8414-style metadata for OpenID Connect).")
                .operationId("openidConfiguration")
                .responses(new ApiResponses().addApiResponse("200",
                        new ApiResponse().description("JSON metadata"))));
    }

    private static PathItem oauthAuthorizationServerMetadataPathItem() {
        return new PathItem().get(new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("Authorization server metadata")
                .description("OAuth 2.0 authorization server metadata (RFC 8414).")
                .operationId("oauthAuthorizationServerMetadata")
                .responses(new ApiResponses().addApiResponse("200",
                        new ApiResponse().description("JSON metadata"))));
    }

    private static PathItem oauth2AuthorizePathItem() {
        Operation op = new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("Authorization endpoint")
                .description("""
                        Browser-based OAuth 2.0 / OIDC authorization endpoint. Unauthenticated users are \
                        redirected to the login page. For machine clients, use the token endpoint with the \
                        appropriate grant.""")
                .operationId("oauth2Authorize")
                .addParametersItem(queryParam("response_type", true, "Typically `code` for authorization code flow"))
                .addParametersItem(queryParam("client_id", true, "Registered client identifier"))
                .addParametersItem(queryParam("redirect_uri", true, "Must match a registered redirect URI"))
                .addParametersItem(queryParam("scope", false, "Space-separated scopes (e.g. `openid profile`)"))
                .addParametersItem(queryParam("state", false, "Opaque value for CSRF protection"))
                .addParametersItem(queryParam("nonce", false, "OIDC nonce for ID token"))
                .addParametersItem(queryParam("code_challenge", false, "PKCE code challenge"))
                .addParametersItem(queryParam("code_challenge_method", false, "PKCE method (e.g. `S256`)"))
                .responses(new ApiResponses()
                        .addApiResponse("302", new ApiResponse().description("Redirect to login or to redirect_uri with code"))
                        .addApiResponse("400", new ApiResponse().description("Invalid request")));
        return new PathItem().get(op);
    }

    private static PathItem oauth2TokenPathItem() {
        ObjectSchema form = new ObjectSchema();
        StringSchema grantTypeSchema = new StringSchema();
        grantTypeSchema.description("OAuth 2.0 grant type");
        grantTypeSchema.setEnum(List.of("authorization_code", "client_credentials", "refresh_token"));
        form.addProperty("grant_type", grantTypeSchema);
        form.addProperty("code", new StringSchema().description("Authorization code (authorization_code grant)"));
        form.addProperty("redirect_uri", new StringSchema().description("Same redirect_uri as in /oauth2/authorize"));
        form.addProperty("client_id", new StringSchema());
        form.addProperty("client_secret", new StringSchema());
        form.addProperty("refresh_token", new StringSchema().description("Refresh token (refresh_token grant)"));
        form.addProperty("scope", new StringSchema().description("Optional scope (some grants)"));
        form.addProperty("code_verifier", new StringSchema().description("PKCE code verifier"));

        Content content = new Content();
        io.swagger.v3.oas.models.media.MediaType mt =
                new io.swagger.v3.oas.models.media.MediaType().schema(form);
        content.addMediaType("application/x-www-form-urlencoded", mt);

        Operation op = new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("Token endpoint")
                .description("Issues access tokens (and optionally refresh / ID tokens) per grant type.")
                .operationId("oauth2Token")
                .requestBody(new io.swagger.v3.oas.models.parameters.RequestBody()
                        .required(true)
                        .content(content))
                .responses(new ApiResponses()
                        .addApiResponse("200", new ApiResponse().description("Token response (JSON)"))
                        .addApiResponse("400", new ApiResponse().description("Invalid client or request"))
                        .addApiResponse("401", new ApiResponse().description("Client authentication failed")));
        return new PathItem().post(op);
    }

    private static PathItem oauth2JwksPathItem() {
        return new PathItem().get(new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("JSON Web Key Set")
                .description("Public keys for validating JWTs issued by this authorization server.")
                .operationId("oauth2Jwks")
                .responses(new ApiResponses()
                        .addApiResponse("200", new ApiResponse().description("JWK Set JSON"))));
    }

    private static PathItem userInfoPathItem() {
        Operation op = new Operation()
                .tags(List.of(TAG_AUTHORIZATION_SERVER))
                .summary("OpenID Connect UserInfo")
                .description("Returns claims for the authenticated end-user; requires a valid access token with appropriate scope.")
                .operationId("oidcUserInfo")
                .addSecurityItem(new SecurityRequirement().addList("bearerJwt", List.of()))
                .responses(new ApiResponses()
                        .addApiResponse("200", new ApiResponse().description("UserInfo JSON"))
                        .addApiResponse("401", new ApiResponse().description("Missing or invalid token")));
        return new PathItem().get(op);
    }

    private static Parameter queryParam(String name, boolean required, String description) {
        return new QueryParameter()
                .name(name)
                .required(required)
                .description(description)
                .schema(new StringSchema());
    }
}
