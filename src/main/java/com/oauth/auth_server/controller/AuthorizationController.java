package com.oauth.auth_server.controller;

import com.oauth.auth_server.oauth2.authorization.AuthorizationCodeIssuedToken;
import com.oauth.auth_server.oauth2.authorization.ConsentRequiredException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationToken;
import com.oauth.auth_server.service.AuthorizationConsentService;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
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

    private final OAuth2AuthorizationCodeRequestAuthenticationProvider provider;
    private final AuthorizationConsentService consentService;

    @GetMapping("/oauth2/authorize")
    public Object authorize(
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @AuthenticationPrincipal UserDetails user,
            HttpServletRequest request,
            Model model
    ) {
        // client_id 파라미터 자체가 없는 경우 → redirect_uri 를 신뢰할 수 없으므로 400
        if (clientId == null) {
            return ResponseEntity.badRequest().build();
        }

        String[] scopeValues = request.getParameterValues("scope");
        int rawScopeParamCount = scopeValues != null ? scopeValues.length : 0;

        OAuth2AuthorizationCodeRequestAuthenticationToken token =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        responseType, clientId, redirectUri,
                        splitScopes(scope), state,
                        user.getUsername(), rawScopeParamCount);

        try {
            AuthorizationCodeIssuedToken issued = provider.process(token);
            return buildCodeRedirect(issued);

        } catch (ConsentRequiredException e) {
            model.addAttribute("client", e.getRegisteredClient());
            model.addAttribute("username", e.getUsername());
            model.addAttribute("requestedScopes", e.getRequestedScopes());
            model.addAttribute("responseType", responseType);
            model.addAttribute("clientId", clientId);
            model.addAttribute("redirectUri", redirectUri);
            model.addAttribute("scope", scope == null ? "" : scope);
            model.addAttribute("state", state == null ? "" : state);
            return "oauth2/consent";

        } catch (OAuth2AuthorizationCodeRequestAuthenticationException e) {
            if (e.getRedirectUri() != null) {
                return buildErrorRedirect(e.getRedirectUri(), e.getError().getErrorCode(), e.getState());
            }
            return ResponseEntity.badRequest().build();
        }
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
        if ("deny".equals(action)) {
            return buildErrorRedirect(redirectUri, "access_denied", state);
        }

        String username = user.getUsername();
        List<String> scopes = splitScopes(scope);

        consentService.saveConsent(username, clientId, scopes);
        AuthorizationCodeIssuedToken issued = provider.issueCode(clientId, username, redirectUri, state, scopes);
        return buildCodeRedirect(issued);
    }

    private ResponseEntity<Void> buildCodeRedirect(AuthorizationCodeIssuedToken issued) {
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(issued.getRedirectUri())
                .queryParam("code", issued.getCode());
        if (issued.getState() != null && !issued.getState().isBlank()) {
            builder.queryParam("state", issued.getState());
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(builder.toUriString()))
                .build();
    }

    private ResponseEntity<Void> buildErrorRedirect(String redirectUri, String error, String state) {
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(redirectUri)
                .queryParam("error", error);
        if (state != null && !state.isBlank()) {
            builder.queryParam("state", state);
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(builder.toUriString()))
                .build();
    }

    private List<String> splitScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        return Arrays.stream(scope.trim().split("\\s+"))
                .filter(s -> !s.isBlank())
                .distinct()
                .toList();
    }
}
