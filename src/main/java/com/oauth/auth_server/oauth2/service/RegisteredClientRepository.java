package com.oauth.auth_server.oauth2.service;

import com.oauth.auth_server.oauth2.core.RegisteredClient;
import java.util.Optional;

public interface RegisteredClientRepository {

    Optional<RegisteredClient> findByClientId(String clientId);
}