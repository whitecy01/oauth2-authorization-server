package com.oauth.auth_server.controller;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.config.SecurityConfig;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * TokenController - 클라이언트 인증 검증 유닛 테스트
 *
 * RFC 6749 §3.2.1 / §5.2 기준:
 * - 클라이언트 인증 실패 → 401 invalid_client + WWW-Authenticate 헤더
 */
@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
class TokenControllerClientAuthTest {

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
    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    private static String basicAuth(String clientId, String clientSecret) {
        String encoded = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    /**
     * Authorization 헤더도, client_id/client_secret 폼 파라미터도 없으면
     * 클라이언트 인증 자체가 불가능하므로 invalid_client 를 반환해야 한다.
     */
    @Test
    void token_withoutAnyClientCredentials_returnsInvalidClient() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
    }

    /**
     * client_id 만 있고 client_secret 이 없으면 invalid_client 를 반환해야 한다.
     */
    @Test
    void token_withoutClientSecret_returnsInvalidClient() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", "test-client"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
    }

    /**
     * 등록되지 않은 client_id 로 요청하면 invalid_client 를 반환해야 한다.
     */
    @Test
    void token_withUnregisteredClientId_returnsInvalidClient() throws Exception {
        given(clientRepository.findByClientIdAndActiveTrue("unknown-client"))
                .willReturn(Optional.empty());

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, basicAuth("unknown-client", "secret"))
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
    }

    /**
     * client_secret 이 일치하지 않으면 invalid_client 를 반환해야 한다.
     */
    @Test
    void token_withWrongClientSecret_returnsInvalidClient() throws Exception {
        OauthClient client = new OauthClient("test-client", "correct-secret", true, "Test Client");
        given(clientRepository.findByClientIdAndActiveTrue("test-client"))
                .willReturn(Optional.of(client));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, basicAuth("test-client", "wrong-secret"))
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
    }

    /**
     * active=false 인 클라이언트는 findByClientIdAndActiveTrue 에서 걸러지므로
     * invalid_client 를 반환해야 한다.
     */
    @Test
    void token_withInactiveClient_returnsInvalidClient() throws Exception {
        given(clientRepository.findByClientIdAndActiveTrue("inactive-client"))
                .willReturn(Optional.empty());

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, basicAuth("inactive-client", "secret"))
                        .param("grant_type", "authorization_code")
                        .param("code", DUMMY_CODE)
                        .param("redirect_uri", REDIRECT_URI))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
    }
}