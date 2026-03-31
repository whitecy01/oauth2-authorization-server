package com.oauth.auth_server.controller;

import com.oauth.auth_server.oauth2.core.OAuth2AccessToken;
import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.token.AuthorizationCodeTokenProvider;
import com.oauth.auth_server.oauth2.token.AuthorizationCodeTokenRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class TokenController {

    private final AuthorizationCodeTokenProvider provider;

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
    public ResponseEntity<Map<String, Object>> issueAccessToken(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam(value = "grant_type", required = false) List<String> grantTypes,
            @RequestParam(value = "code", required = false) List<String> codes,
            @RequestParam(value = "redirect_uri", required = false) List<String> redirectUris,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret
    ) {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                grantTypes, codes, redirectUris, clientId, clientSecret, authorizationHeader);
        try {
            OAuth2AccessToken token = provider.process(request);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", token.getTokenValue());
            body.put("token_type", "Bearer");
            body.put("expires_in", token.getExpiresInSeconds());
            return ResponseEntity.ok(body);
        } catch (OAuth2AuthorizationException ex) {
            String errorCode = ex.getError().getErrorCode();
            if ("invalid_client".equals(errorCode)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth2/token\"")
                        .body(errorBody(errorCode, ex.getError().getDescription()));
            }
            return ResponseEntity.badRequest().body(errorBody(errorCode, ex.getError().getDescription()));
        }
    }

    private Map<String, Object> errorBody(String errorCode, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", errorCode);
        body.put("error_description", description);
        return body;
    }
}
