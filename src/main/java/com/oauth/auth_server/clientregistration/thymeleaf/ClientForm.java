package com.oauth.auth_server.clientregistration.thymeleaf;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClientForm {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private boolean active = true;
    private String redirectUrisCsv;
    private String scopesCsv;
}
