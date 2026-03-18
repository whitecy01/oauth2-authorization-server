package com.oauth.auth_server.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.config.SecurityConfig;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * TokenController - grant_type 파라미터 검증 유닛 테스트
 *
 * RFC 6749 §5.2 기준:
 * - grant_type 은 REQUIRED
 * - 누락/빈값/중복 → invalid_request
 * - 지원하지 않는 grant_type → unsupported_grant_type
 */
@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
class TokenControllerGrantTypeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OauthClientRepository clientRepository;

    @MockitoBean
    private OauthClientRedirectUriRepository redirectUriRepository;

    @MockitoBean
    private OauthAuthorizationCodeRepository authorizationCodeRepository;

    @MockitoBean
    private OauthAccessTokenRepository accessTokenRepository;

    private static final String DUMMY_CODE = "dummy-code";
    private static final String DUMMY_REDIRECT_URI = "http://localhost:8080/callback";

    /**
     * grant_type 파라미터가 없으면 invalid_request 를 반환해야 한다.
     * RFC 6749 §4.1.3: grant_type is REQUIRED
     */
    @Test
    void token_withoutGrantType_returnsInvalidRequest() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * grant_type 값이 빈 문자열이면 invalid_request 를 반환해야 한다.
     */
    @Test
    void token_withBlankGrantType_returnsInvalidRequest() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * grant_type 이 중복으로 전송되면 invalid_request 를 반환해야 한다.
     * 예: grant_type=authorization_code&grant_type=refresh_token
     */
    @Test
    void token_withDuplicateGrantType_returnsInvalidRequest() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("grant_type", "refresh_token")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    /**
     * grant_type=refresh_token 은 지원하지 않으므로 unsupported_grant_type 을 반환해야 한다.
     */
    @Test
    void token_withRefreshTokenGrantType_returnsUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    /**
     * grant_type=client_credentials 는 지원하지 않으므로 unsupported_grant_type 을 반환해야 한다.
     */
    @Test
    void token_withClientCredentialsGrantType_returnsUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    /**
     * grant_type=foo 처럼 알 수 없는 값은 unsupported_grant_type 을 반환해야 한다.
     */
    @Test
    void token_withUnknownGrantType_returnsUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "foo")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", DUMMY_REDIRECT_URI))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }
}