package com.oauth.auth_server.resourceserver;

import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/resource")
@RequiredArgsConstructor
public class ResourceServerController {

    private final ResourceServerService resourceServerService;

    @GetMapping("/me")
    public ResponseEntity<?> me(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader
    ) {
        String bearerToken = resolveBearerToken(authorizationHeader);
        if (bearerToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                    .body(errorBody("invalid_token", "bearer token is required"));
        }

        try {
            return ResponseEntity.ok(resourceServerService.getUserProfile(bearerToken));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                    .body(errorBody("invalid_token", ex.getMessage()));
        }
    }

    private String resolveBearerToken(String authorizationHeader) {
        if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }
        return authorizationHeader.substring(7).trim();
    }

    private Map<String, Object> errorBody(String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return body;
    }
}
