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
 * TokenController - code 파라미터 검증 유닛 테스트
 *
 * RFC 6749 §4.1.3 기준:
 * - code 는 REQUIRED
 * - 누락/빈값/중복 → invalid_request
 * - 존재하지 않는 code → invalid_grant
 */
@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
class TokenControllerCodeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthorizationCodeTokenProvider provider;

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String BASIC_AUTH = "Basic " + Base64.getEncoder()
            .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));

    /**
     * code 파라미터가 없으면 invalid_request 를 반환해야 한다.
     * RFC 6749 §4.1.3: code is REQUIRED
     */
    @Test
    void token_withoutCode_returnsInvalidRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_request", "code is required", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * code 값이 빈 문자열이면 invalid_request 를 반환해야 한다.
     */
    @Test
    void token_withBlankCode_returnsInvalidRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_request", "code is required", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", "")
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * code 가 중복으로 전송되면 invalid_request 를 반환해야 한다.
     * 예: code=abc&code=def
     */
    @Test
    void token_withDuplicateCode_returnsInvalidRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_request", "code must not be duplicated", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", "code-value-1")
                        .param("code", "code-value-2")
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * 존재하지 않는 code 를 제출하면 invalid_grant 를 반환해야 한다.
     * RFC 6749 §5.2: invalid_grant
     */
    @Test
    void token_withNonExistentCode_returnsInvalidGrant() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", "authorization code is invalid", null)));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, BASIC_AUTH)
                        .param("grant_type", "authorization_code")
                        .param("code", "nonexistent-code")
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}
