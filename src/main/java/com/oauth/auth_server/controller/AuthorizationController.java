package com.oauth.auth_server.controller;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@RequiredArgsConstructor
public class AuthorizationController {
    private final OauthClientRepository clientRepository;
    private final OauthAuthorizationCodeRepository codeRepository;
    private final AuthorizationConsentService consentService;

    /**
     * 인가 엔드포인트 (아주 단순한 happy-path)
     * 예:
     * /oauth2/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback
     */
    @RequestMapping(value = "/oauth2/authorize", method = {RequestMethod.GET, RequestMethod.POST}, params = "response_type")
    public Object authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @AuthenticationPrincipal UserDetails user,
            Model model
    ) {
        String username = user.getUsername();
        List<String> requestedScopes = splitScopes(scope);
        OauthClient client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("invalid client"));

        if (consentService.hasConsent(username, client.getClientId(), requestedScopes)) {
            return issueAuthorizationCode(client, username, redirectUri, state);
        }
        System.out.println("AuthorizationController : " + client.getClientId());
        model.addAttribute("client", client);
        model.addAttribute("username", username);
        model.addAttribute("requestedScopes", requestedScopes);
        model.addAttribute("responseType", responseType);
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("scope", scope == null ? "" : scope);
        model.addAttribute("state", state == null ? "" : state);
        return "oauth2/consent";
    }

    @RequestMapping(value = "/oauth2/authorize", method = RequestMethod.POST, params = "action")
    public ResponseEntity<Void> submitConsent(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam("action") String action,
            @AuthenticationPrincipal UserDetails user
    ) {
        String username = user.getUsername();
        List<String> requestedScopes = splitScopes(scope);
        OauthClient client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("invalid client"));

        if ("deny".equals(action)) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(buildErrorRedirectUri(redirectUri, state)))
                    .build();
        }

        consentService.saveConsent(username, client.getClientId(), requestedScopes);
        return issueAuthorizationCode(client, username, redirectUri, state);
    }

    private List<String> splitScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }

        return Arrays.stream(scope.trim().split("\\s+"))
                .filter(value -> !value.isBlank())
                .distinct()
                .toList();
    }

    private ResponseEntity<Void> issueAuthorizationCode(
            OauthClient client,
            String username,
            String redirectUri,
            String state
    ) {
        String code = UUID.randomUUID().toString().replace("-", "");
        Instant expiresAt = Instant.now().plusSeconds(600);

        codeRepository.save(new OauthAuthorizationCode(
                code,
                client.getClientId(),
                username,
                redirectUri,
                state,
                expiresAt
        ));

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("code", code);
        if (state != null && !state.isBlank()) {
            builder.queryParam("state", state);
        }

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(builder.toUriString()))
                .build();
    }

    private String buildErrorRedirectUri(String redirectUri, String state) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", "access_denied");
        if (state != null && !state.isBlank()) {
            builder.queryParam("state", state);
        }
        return builder.toUriString();
    }
}
