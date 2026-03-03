package com.oauth.auth_server.clientregistration.service;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import com.oauth.auth_server.clientregistration.entity.OauthClientScope;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientScopeRepository;
import com.oauth.auth_server.clientregistration.thymeleaf.ClientForm;
import java.util.Comparator;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class ClientService {
    private final OauthClientRepository clientsRepo;
    private final OauthClientRedirectUriRepository redirectRepo;
    private final OauthClientScopeRepository scopeRepo;

    @Transactional(readOnly = true)
    public List<ClientSummary> list() {
        return clientsRepo.findAll().stream()
                .map(client -> new ClientSummary(
                        client,
                        redirectRepo.findByClient_ClientId(client.getClientId()).stream()
                                .map(OauthClientRedirectUri::getRedirectUri)
                                .toList(),
                        scopeRepo.findByClient_ClientId(client.getClientId()).stream()
                                .map(OauthClientScope::getScope)
                                .toList()
                ))
                .sorted(Comparator.comparing(summary -> summary.client().getClientId()))
                .toList();
    }

    @Transactional(readOnly = true)
    public ClientDetail getDetail(String clientId) {
        OauthClient client = clientsRepo.findById(clientId).orElseThrow();
        List<String> redirectUris = redirectRepo.findByClient_ClientId(clientId)
                .stream().map(OauthClientRedirectUri::getRedirectUri).toList();
        List<String> scopes = scopeRepo.findByClient_ClientId(clientId)
                .stream().map(OauthClientScope::getScope).toList();

        return new ClientDetail(client, redirectUris, scopes);
    }

    @Transactional
    public void create(ClientForm form) {
        OauthClient client = new OauthClient(
                form.getClientId(),
                form.getClientSecret(),
                form.isActive(),
                form.getClientName()
        );
        clientsRepo.save(client);

        for (String uri : splitCsv(form.getRedirectUrisCsv())) {
            redirectRepo.save(new OauthClientRedirectUri(client, uri));
        }
        for (String scope : splitCsv(form.getScopesCsv())) {
            scopeRepo.save(new OauthClientScope(client, scope));
        }
    }

    private List<String> splitCsv(String csv) {
        if (!StringUtils.hasText(csv)) return List.of();
        return List.of(csv.split(","))
                .stream()
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }

    public record ClientSummary(OauthClient client, List<String> redirectUris, List<String> scopes) {}
    public record ClientDetail(OauthClient client, List<String> redirectUris, List<String> scopes) {}
}
