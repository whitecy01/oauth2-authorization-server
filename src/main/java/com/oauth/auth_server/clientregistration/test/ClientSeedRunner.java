package com.oauth.auth_server.clientregistration.test;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import com.oauth.auth_server.clientregistration.entity.OauthClientScope;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientScopeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ClientSeedRunner implements ApplicationRunner {

    private final OauthClientRepository clientsRepo;
    private final OauthClientRedirectUriRepository redirectRepo;
    private final OauthClientScopeRepository scopeRepo;

    @Override
    public void run(ApplicationArguments args) {
        if (clientsRepo.existsById("test-client")) return;

        OauthClient c = new OauthClient(
                "test-client",
                "secret",
                true,
                "Test Client"
        );
        clientsRepo.save(c);

        redirectRepo.save(new OauthClientRedirectUri(c, "http://localhost:8080/callback"));
        redirectRepo.save(new OauthClientRedirectUri(c, "http://localhost:8080/callback2"));

        scopeRepo.save(new OauthClientScope(c, "read"));
        scopeRepo.save(new OauthClientScope(c, "write"));
    }
}
