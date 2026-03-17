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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
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
    @GetMapping("/oauth2/authorize")
    public Object authorize(
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @AuthenticationPrincipal UserDetails user,
            Model model
    ) {
        /**
         * responseType 이 없거나 빈 문자열 및 값이 없을 때
         */
        if (responseType == null || responseType.isBlank()) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(buildErrorRedirectUri(redirectUri, "invalid_request", state)))
                    .build();
        }

        /**
         * responseType에서 지원하지 않는 인증일 때
         */
        if (!responseType.equals("code")){
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(buildErrorRedirectUri(redirectUri, "unsupported_response_type", state)))
                    .build();
        }

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

    @PostMapping("/oauth2/authorize")
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
                    .location(URI.create(buildErrorRedirectUri(redirectUri, "access_denied", state)))
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

    private String buildErrorRedirectUri(String redirectUri, String error, String state) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", error);
        if (state != null && !state.isBlank()) {
            builder.queryParam("state", state);
        }
        return builder.toUriString();
    }
}
