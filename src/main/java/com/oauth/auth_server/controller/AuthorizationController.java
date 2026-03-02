package com.oauth.auth_server.controller;

import com.oauth.auth_server.oauth.SimpleClient;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthorizationController {

    // 지금은 클라이언트 정보를 메모리에 하드코딩
    private final Map<String, SimpleClient> clients = Map.of(
            "test-client",
            new SimpleClient("test-client", "http://localhost:3000/callback")
    );

    // code 저장소 (code -> username)
    private final Map<String, String> codes = new ConcurrentHashMap<>();

    /**
     * 인가 엔드포인트 (아주 단순한 happy-path)
     * 예:
     * /oauth2/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback
     */
    @GetMapping("/oauth2/authorize")
    public void authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @AuthenticationPrincipal UserDetails user,
            HttpServletResponse response
    ) throws IOException {

        /**
         * 여기까지 왔으면 보통 user는 항상 있음 (SecurityConfig에서 인증 강제)
         * 그래도 안전하게 방어
         */
        if (user == null) {
            response.sendRedirect("/login");
            return;
        }

        /**
         * client_id 검증
         */
        SimpleClient client = clients.get(clientId);
        if (client == null) {
            response.sendError(400, "invalid_client");
            return;
        }

        System.out.println("=== Authorization Request ===");
        System.out.println("response_type = " + responseType);
        System.out.println("client_id = " + clientId);
        System.out.println("redirect_uri = " + redirectUri);
        System.out.println("scope = " + scope);
        System.out.println("state = " + state);

        /**
         * redirect_uri 검증 (등록된 redirect_uri와 정확히 일치해야 함)
         */
        if (!client.getRedirectUri().equals(redirectUri)) {
            response.sendError(400, "invalid_redirect_uri");
            return;
        }

        /**
         * authorization code 발급
         */
        String code = UUID.randomUUID().toString();

        /**
         *  code 저장 (나중에 토큰 엔드포인트에서 이걸로 사용자 찾음)
         */
        codes.put(code, user.getUsername());

        /**
         * 리다이렉트
         */
        response.sendRedirect(redirectUri + "?code=" + code);
    }


}
