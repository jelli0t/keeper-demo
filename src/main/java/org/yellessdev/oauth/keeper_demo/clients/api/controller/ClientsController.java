package org.yellessdev.oauth.keeper_demo.clients.api.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientRequest;
import org.yellessdev.oauth.keeper_demo.clients.api.dto.RegisterClientResponse;
import org.yellessdev.oauth.keeper_demo.clients.api.ClientsApi;
import org.yellessdev.oauth.keeper_demo.service.OAuth2ClientRegistrationService;

@RestController
public class ClientsController implements ClientsApi {

    private final OAuth2ClientRegistrationService registrationService;

    public ClientsController(OAuth2ClientRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @Override
    public ResponseEntity<RegisterClientResponse> register(@Valid @RequestBody RegisterClientRequest request) {
        RegisterClientResponse body = registrationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }
}
