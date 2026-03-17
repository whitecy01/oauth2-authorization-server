package com.oauth.auth_server.controller;

import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import com.oauth.auth_server.clientregistration.entity.OauthClientScope;
import com.oauth.auth_server.clientregistration.repository.OauthClientRedirectUriRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientScopeRepository;
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
 * AuthorizationController - scope 파라미터 검증 유닛 테스트
 *
 * RFC 6749 §3.3 기준:
 * - scope 는 선택 파라미터
 * - 공백으로 구분된 문자열 (scope=read write), 동일 파라미터 중복 불가 (scope=read&scope=write)
 * - 요청된 scope 는 서버에 등록된 범위 내이어야 함
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerScopeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OauthClientRepository clientRepository;

    @MockitoBean
    private OauthClientRedirectUriRepository clientRedirectUriRepository;

    @MockitoBean
    private OauthClientScopeRepository clientScopeRepository;

    @MockitoBean
    private OauthAuthorizationCodeRepository codeRepository;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private OauthClient client;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    @BeforeEach
    void setUp() {
        client = new OauthClient("test-client", "secret", true, "Test Client");
        given(clientRepository.findByClientIdAndActiveTrue("test-client")).willReturn(Optional.of(client));
        given(clientRedirectUriRepository.findByClient_ClientId("test-client"))
                .willReturn(List.of(new OauthClientRedirectUri(client, REDIRECT_URI)));
        given(clientScopeRepository.findByClient_ClientId("test-client"))
                .willReturn(List.of(
                        new OauthClientScope(client, "read"),
                        new OauthClientScope(client, "write")
                ));
    }

    /**
     * scope 없음 → 선택 파라미터이므로 정상 처리 (동의 화면 200 OK)
     */
    @Test
    void authorize_withoutScope_proceeds() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    /**
     * scope=read → 등록된 단일 scope, 정상 처리
     */
    @Test
    void authorize_withSingleValidScope_proceeds() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    /**
     * scope=read write → 공백 구분 복수 scope, 정상 처리
     */
    @Test
    void authorize_withMultipleValidScopes_proceeds() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read write")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    /**
     * scope=read&scope=write → 동일 파라미터 중복 전송 불가, invalid_scope
     * RFC 6749 §3.3: scope 파라미터는 한 번만 전송해야 함
     */
    @Test
    void authorize_withDuplicateScopeParam_returnsInvalidScope() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("scope", "write")   // 동일 파라미터 두 번
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_scope")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }

    /**
     * 등록되지 않은 scope 요청 → invalid_scope
     * RFC 6749 §4.1.2.1: 허용 범위를 벗어난 scope
     */
    @Test
    void authorize_withUnregisteredScope_returnsInvalidScope() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "admin")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_scope")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }

    /**
     * 형식이 깨진 scope (RFC 6749 §3.3 허용 문자 외) → invalid_scope
     * 허용: %x21, %x23-5B, %x5D-7E  /  불허: 공백 외 제어문자, '"', '\'
     */
    @Test
    void authorize_withMalformedScope_returnsInvalidScope() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "re@d")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_scope")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }
}