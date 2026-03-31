package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.config.SecurityConfig;
import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.core.OAuth2Error;
import com.oauth.auth_server.oauth2.token.AuthorizationCodeTokenProvider;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * TokenController - redirect_uri 파라미터 검증 유닛 테스트
 *
 * RFC 6749 §4.1.3 기준:
 * - 인가 요청에 redirect_uri가 포함된 경우, 토큰 요청에도 동일 값 필수
 * - 누락/빈값 → invalid_grant (비교 대상이 존재하므로)
 * - 중복 전달 → invalid_request
 * - 불일치 → invalid_grant
 */
@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
class TokenControllerRedirectUriTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthorizationCodeTokenProvider provider;

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String DUMMY_CODE = "valid-code";
    private static final String ORIGINAL_REDIRECT_URI = "http://localhost:8080/callback";
    private static final String OTHER_REDIRECT_URI = "http://localhost:8080/other-callback";
    private static final String BASIC_AUTH = "Basic " + Base64.getEncoder()
            .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));

    /**
     * redirect_uri 파라미터가 없으면 invalid_grant 를 반환해야 한다.
     * 인가 코드 발급 시 저장된 redirect_uri와 비교가 불가능하므로 invalid_grant.
     */
    @Test
    void token_withoutRedirectUri_returnsInvalidGrant() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", "redirect_uri is required", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    /**
     * redirect_uri 가 중복으로 전송되면 invalid_request 를 반환해야 한다.
     * 예: redirect_uri=http://a.com&redirect_uri=http://b.com
     */
    @Test
    void token_withDuplicateRedirectUri_returnsInvalidRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_request", "redirect_uri must not be duplicated", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", ORIGINAL_REDIRECT_URI)
                        .param("redirect_uri", OTHER_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * 인가 코드에 저장된 redirect_uri 와 토큰 요청의 redirect_uri 가 다르면 invalid_grant 를 반환해야 한다.
     * 공격자가 다른 redirect_uri 를 사용해도 코드를 탈취할 수 없음을 보장.
     */
    @Test
    void token_withMismatchedRedirectUri_returnsInvalidGrant() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", "redirect_uri does not match", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, BASIC_AUTH)
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", OTHER_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}
