package org.yellessdev.oauth.keeper_demo.clients.api;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientRequest;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientResponse;

@RequestMapping("/v1/clients")
public interface ClientsApi {

    @PostMapping(
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    ResponseEntity<RegisterClientResponse> register(RegisterClientRequest request);
}
