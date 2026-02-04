package com.oauth.auth_server.test.controller;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthDebugController {


    /**
     * 사용자가 http://localhost:8080/oauth2/authorize?client_id=test-client 이 URL로 로그인 시도
     * @param clientId
     * @param user
     * @return
     */
    @GetMapping("/oauth2/authorize")
    public String authorizeDebug(
            @RequestParam(name = "client_id", required = false) String clientId,
            @AuthenticationPrincipal UserDetails user
    ) {
        return "OK user=" + user.getUsername();
    }

    /**
     * 로그인 한 사용자 누구인지 다시 보기
     * @param user
     * @return
     */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal UserDetails user) {
        return Map.of(
                "username", user.getUsername(),
                "authorities", user.getAuthorities()
        );
    }


}
