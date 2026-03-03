package com.oauth.auth_server.controller;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequiredArgsConstructor
public class AuthorizationController {
    private final OauthClientRepository clientRepository;
    private final OauthAuthorizationCodeRepository codeRepository;

    /**
     * 인가 엔드포인트 (아주 단순한 happy-path)
     * 예:
     * /oauth2/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback
     */
//    @GetMapping("/oauth2/authorize")
//    public ResponseEntity<Void> authorize(
//            @RequestParam("response_type") String responseType,
//            @RequestParam("client_id") String clientId,
//            @RequestParam("redirect_uri") String redirectUri,
//            @RequestParam(value = "scope", required = false) String scope,
//            @RequestParam(value = "state", required = false) String state,
//            @AuthenticationPrincipal UserDetails user,
//            HttpServletResponse response
//    ) throws IOException {
//        String username = user.getUsername();
//
//        OauthClient client = clientRepository.findByClientIdAndActiveTrue(clientId)
//                .orElseThrow(() -> new IllegalArgumentException("invalid client"));
////        String finalRedirectUri = (redirectUri != null) ? redirectUri : client.getRedirectUri();
//
//        String code = UUID.randomUUID().toString().replace("-", "");
//        Instant expiresAt = Instant.now().plusSeconds(300);
//
////        codeRepository.save(new OauthAuthorizationCode(
////                code,
////                clientId,
////                username,
////                finalRedirectUri,
////                state,
////                expiresAt
////        ));
//
//        // 5) redirect
////        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(finalRedirectUri)
////                .queryParam("code", code);
////        if (state != null) b.queryParam("state", state);
//
//        return ResponseEntity.status(HttpStatus.FOUND)
//                .location(URI.create(b.toUriString()))
//                .build();
//    }


}
