package com.oauth.auth_server.oauth2.service;

import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import com.oauth.auth_server.clientregistration.entity.OauthClientScope;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientScopeRepository;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OauthClientRepository clientRepository;
    private final OauthClientRedirectUriRepository redirectUriRepository;
    private final OauthClientScopeRepository scopeRepository;

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        return clientRepository.findByClientIdAndActiveTrue(clientId)
                .map(client -> {
                    List<String> redirectUris = redirectUriRepository
                            .findByClient_ClientId(clientId)
                            .stream()
                            .map(OauthClientRedirectUri::getRedirectUri)
                            .toList();

                    List<String> scopes = scopeRepository
                            .findByClient_ClientId(clientId)
                            .stream()
                            .map(OauthClientScope::getScope)
                            .toList();

                    RegisteredClient.Builder builder = RegisteredClient.builder()
                            .clientId(client.getClientId())
                            .clientSecret(client.getClientSecret())
                            .active(client.isActive());
                    redirectUris.forEach(builder::redirectUri);
                    scopes.forEach(builder::scope);
                    return builder.build();
                });
    }
}
