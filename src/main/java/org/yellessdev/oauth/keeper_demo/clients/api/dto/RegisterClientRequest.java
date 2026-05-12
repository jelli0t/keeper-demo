package org.yellessdev.oauth.keeper_demo.clients.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.io.Serializable;
import java.util.List;

public record RegisterClientRequest(
        @NotBlank String clientId,
        String clientName,
        /** Plain secret; optional if only public client methods are used, otherwise generated when absent. */
        String clientSecret,
        @NotEmpty List<String> clientAuthenticationMethods,
        @NotEmpty List<String> authorizationGrantTypes,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        @NotEmpty List<String> scopes
) implements Serializable { }
