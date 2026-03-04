package com.oauth.auth_server.service;

import com.oauth.auth_server.entity.OauthAuthorizationConsent;
import com.oauth.auth_server.repository.OauthAuthorizationConsentRepository;
import java.util.List;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class AuthorizationConsentService {

    private final OauthAuthorizationConsentRepository consentRepository;

    @Transactional(readOnly = true)
    public boolean hasConsent(String username, String clientId, List<String> requestedScopes) {
        if (requestedScopes.isEmpty()) {
            return true;
        }

        Set<String> consentedScopes = consentRepository.findByUsernameAndClientId(username, clientId).stream()
                .map(OauthAuthorizationConsent::getScope)
                .collect(java.util.stream.Collectors.toSet());

        return consentedScopes.containsAll(requestedScopes);
    }

    @Transactional
    public void saveConsent(String username, String clientId, List<String> scopes) {
        List<String> existingScopes = consentRepository.findByUsernameAndClientId(username, clientId).stream()
                .map(OauthAuthorizationConsent::getScope)
                .toList();

        scopes.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .filter(scope -> !existingScopes.contains(scope))
                .forEach(scope -> consentRepository.save(new OauthAuthorizationConsent(clientId, username, scope)));
    }
}
