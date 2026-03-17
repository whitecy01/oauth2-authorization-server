package com.oauth.auth_server.controller;

import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - redirect_uri 파라미터 검증 유닛 테스트
 *
 * RFC 6749 §3.1.2, §4.1.2.1 기준:
 * - redirect_uri 는 선택 파라미터 (등록 URI 가 1개면 생략 가능, 여러 개면 필수)
 * - redirect_uri 를 신뢰할 수 없는 경우 리다이렉트 금지 → 400 직접 반환
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerRedirectUriTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OauthClientRepository clientRepository;

    @MockitoBean
    private OauthClientRedirectUriRepository clientRedirectUriRepository;

    @MockitoBean
    private OauthAuthorizationCodeRepository codeRepository;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private OauthClient client;

    private static final String REGISTERED_URI_1 = "http://localhost:8080/callback";
    private static final String REGISTERED_URI_2 = "http://localhost:8080/callback2";

    @BeforeEach
    void setUp() {
        client = new OauthClient("test-client", "secret", true, "Test Client");
        given(clientRepository.findByClientIdAndActiveTrue("test-client")).willReturn(Optional.of(client));
    }

    /**
     * redirect_uri 생략 + 등록 URI 1개 → 등록된 URI 를 사용해 정상 처리된다.
     * RFC 6749 §3.1.2.3: 등록 URI 가 하나면 redirect_uri 생략 허용
     */
    @Test
    void authorize_withoutRedirectUri_singleRegistered_proceeds() throws Exception {
        given(clientRedirectUriRepository.findByClient_ClientId("test-client"))
                .willReturn(List.of(new OauthClientRedirectUri(client, REGISTERED_URI_1)));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    /**
     * redirect_uri 생략 + 등록 URI 여러 개 → 어디로 보낼지 알 수 없으므로 400
     * RFC 6749 §3.1.2.3: 등록 URI 가 여러 개면 redirect_uri 필수
     */
    @Test
    void authorize_withoutRedirectUri_multipleRegistered_returnsBadRequest() throws Exception {
        given(clientRedirectUriRepository.findByClient_ClientId("test-client"))
                .willReturn(List.of(
                        new OauthClientRedirectUri(client, REGISTERED_URI_1),
                        new OauthClientRedirectUri(client, REGISTERED_URI_2)
                ));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    /**
     * redirect_uri 가 빈 값 → 400
     * RFC 6749 §4.1.2.1: redirect_uri 가 유효하지 않으면 리다이렉트 금지
     */
    @Test
    void authorize_withBlankRedirectUri_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    /**
     * redirect_uri 에 프래그먼트(#) 포함 → 400
     * RFC 6749 §3.1.2: redirect_uri 에 fragment 는 허용되지 않음
     */
    @Test
    void authorize_withFragmentInRedirectUri_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REGISTERED_URI_1 + "#section")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    /**
     * redirect_uri 가 등록된 목록에 없음 → 400
     * RFC 6749 §4.1.2.1: 등록값과 불일치하면 리다이렉트 MUST NOT
     */
    @Test
    void authorize_withUnregisteredRedirectUri_returnsBadRequest() throws Exception {
        given(clientRedirectUriRepository.findByClient_ClientId("test-client"))
                .willReturn(List.of(new OauthClientRedirectUri(client, REGISTERED_URI_1)));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://attacker.com/callback")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }
}
