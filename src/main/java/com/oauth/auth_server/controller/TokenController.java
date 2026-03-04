package com.oauth.auth_server.controller;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.entity.OauthAccessToken;
import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class TokenController {

    private static final long ACCESS_TOKEN_TTL_SECONDS = 3600;

    private final OauthClientRepository clientRepository;
    private final OauthClientRedirectUriRepository redirectUriRepository;
    private final OauthAuthorizationCodeRepository authorizationCodeRepository;
    private final OauthAccessTokenRepository accessTokenRepository;

    @GetMapping("/oauth2/token-page")
    public String tokenPage(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            Model model
    ) {
        model.addAttribute("code", code == null ? "" : code);
        model.addAttribute("redirectUri", redirectUri == null ? "" : redirectUri);
        return "oauth2/token";
    }

    @ResponseBody
    @PostMapping(
            value = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Transactional
    public ResponseEntity<Map<String, Object>> issueAccessToken(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret
    ) {
        if (!"authorization_code".equals(grantType)) {
            return error(HttpStatus.BAD_REQUEST, "unsupported_grant_type", "grant_type must be authorization_code");
        }

        /**
         * Base64로 된 거 꺼내기
         */
        ClientCredentials credentials = resolveClientCredentials(authorizationHeader, clientId, clientSecret);
        if (credentials == null) {
            return invalidClient("client authentication is required");
        }

        OauthClient client = clientRepository.findByClientIdAndActiveTrue(credentials.clientId())
                .filter(found -> found.getClientSecret().equals(credentials.clientSecret()))
                .orElse(null);
        if (client == null) {
            return invalidClient("invalid client credentials");
        }

        boolean redirectUriRegistered = redirectUriRepository.findByClient_ClientId(client.getClientId()).stream()
                .anyMatch(registered -> registered.getRedirectUri().equals(redirectUri));
        if (!redirectUriRegistered) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "redirect_uri is not registered");
        }

        OauthAuthorizationCode authorizationCode = authorizationCodeRepository.findByCode(code).orElse(null);
        if (authorizationCode == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "authorization code is invalid");
        }

        if (authorizationCode.getExpiresAt().isBefore(Instant.now())) {
            authorizationCodeRepository.delete(authorizationCode);
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "authorization code is expired");
        }

        if (!authorizationCode.getClientId().equals(client.getClientId())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "authorization code was not issued to this client");
        }

        if (!authorizationCode.getRedirectUri().equals(redirectUri)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "redirect_uri does not match");
        }

        String accessTokenValue = UUID.randomUUID().toString().replace("-", "");
        Instant expiresAt = Instant.now().plusSeconds(ACCESS_TOKEN_TTL_SECONDS);

        accessTokenRepository.save(new OauthAccessToken(
                accessTokenValue,
                client.getClientId(),
                authorizationCode.getUsername(),
                expiresAt
        ));
        authorizationCodeRepository.delete(authorizationCode);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessTokenValue);
        body.put("token_type", "Bearer");
        body.put("expires_in", ACCESS_TOKEN_TTL_SECONDS);
        return ResponseEntity.ok(body);
    }

    private ClientCredentials resolveClientCredentials(
            String authorizationHeader,
            String clientId,
            String clientSecret
    ) {
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Basic ")) {
            try {
                String encoded = authorizationHeader.substring(6).trim();
                String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
                int delimiterIndex = decoded.indexOf(':');
                if (delimiterIndex < 0) {
                    return null;
                }
                return new ClientCredentials(
                        decoded.substring(0, delimiterIndex),
                        decoded.substring(delimiterIndex + 1)
                );
            } catch (IllegalArgumentException ex) {
                return null;
            }
        }

        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            return null;
        }

        return new ClientCredentials(clientId, clientSecret);
    }

    private ResponseEntity<Map<String, Object>> invalidClient(String description) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth2/token\"")
                .body(errorBody("invalid_client", description));
    }

    private ResponseEntity<Map<String, Object>> error(
            HttpStatus status,
            String errorCode,
            String description
    ) {
        return ResponseEntity.status(status).body(errorBody(errorCode, description));
    }

    private Map<String, Object> errorBody(String errorCode, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", errorCode);
        body.put("error_description", description);
        return body;
    }

    private record ClientCredentials(String clientId, String clientSecret) {
    }
}
