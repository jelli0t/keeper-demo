package org.yellessdev.oauth.keeper_demo.clients.api.dto;

/**
 * @param generatedClientSecret Plain secret shown once when the server generated it; null when the request supplied a secret or the client is public.
 */
public record RegisterClientResponse(
        String id,
        String clientId,
        String clientName,
        String generatedClientSecret
) {
}
