package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - consent 흐름 유닛 테스트
 *
 * GET  /oauth2/authorize : 동의 필요 여부 판단
 * POST /oauth2/authorize : 동의 승인 / 거부 처리
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerConsentTest {

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

    private static final String CLIENT_ID   = "test-client";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String USERNAME     = "user";

    @BeforeEach
    void setUp() {
        client = new OauthClient(CLIENT_ID, "secret", true, "Test Client");
        given(clientRepository.findByClientIdAndActiveTrue(CLIENT_ID)).willReturn(Optional.of(client));
        given(clientRedirectUriRepository.findByClient_ClientId(CLIENT_ID))
                .willReturn(List.of(new OauthClientRedirectUri(client, REDIRECT_URI)));
        given(clientScopeRepository.findByClient_ClientId(CLIENT_ID))
                .willReturn(List.of(
                        new OauthClientScope(client, "read"),
                        new OauthClientScope(client, "write")
                ));
    }

    // -------------------------------------------------------------------------
    // 동의 필요 여부 판단 (GET /oauth2/authorize)
    // -------------------------------------------------------------------------

    /**
     * 기존 동의 없음 → 동의 화면(200 OK) 반환
     */
    @Test
    void authorize_withNoExistingConsent_showsConsentPage() throws Exception {
        given(consentService.hasConsent(eq(USERNAME), eq(CLIENT_ID), any())).willReturn(false);

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isOk());
    }

    /**
     * 같은 scope에 이미 동의함 → 동의 화면 없이 code 바로 발급 (302)
     */
    @Test
    void authorize_withExistingConsent_issuesCodeDirectly() throws Exception {
        given(consentService.hasConsent(eq(USERNAME), eq(CLIENT_ID), any())).willReturn(true);

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", Matchers.containsString("code=")))
                .andExpect(header().string("Location", Matchers.startsWith(REDIRECT_URI)));
    }

    /**
     * 기존 동의보다 넓은 scope 요청 → 동의 화면(200 OK) 반환
     * (hasConsent 가 false 를 반환하는 상황 - write 가 새로 추가됨)
     */
    @Test
    void authorize_withNewScopeNotYetConsented_showsConsentPage() throws Exception {
        given(consentService.hasConsent(eq(USERNAME), eq(CLIENT_ID), any())).willReturn(false);

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read write")   // write 는 새로운 scope
                        .param("state", "state-abc")
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isOk());
    }

    // -------------------------------------------------------------------------
    // 동의 승인 (POST /oauth2/authorize, action=approve)
    // -------------------------------------------------------------------------

    /**
     * 승인 후 redirect_uri 로 code 발급 (302)
     */
    @Test
    void submitConsent_approve_issuesCode() throws Exception {
        mockMvc.perform(post("/oauth2/authorize")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .param("action", "approve")
                        .with(csrf())
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", Matchers.startsWith(REDIRECT_URI)))
                .andExpect(header().string("Location", Matchers.containsString("code=")))
                .andExpect(header().string("Location", Matchers.containsString("state=state-abc")));
    }

//    /**
//     * 승인 시 consentService.saveConsent() 가 호출된다 (consent DB 저장)
//     */
//    @Test
//    void submitConsent_approve_savesConsent() throws Exception {
//        mockMvc.perform(post("/oauth2/authorize")
//                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
//                        .param("client_id", CLIENT_ID)
//                        .param("redirect_uri", REDIRECT_URI)
//                        .param("scope", "read")
//                        .param("state", "state-abc")
//                        .param("action", "approve")
//                        .with(user(USERNAME).roles("USER")));
//
//        verify(consentService).saveConsent(eq(USERNAME), eq(CLIENT_ID), eq(List.of("read")));
//    }

    // -------------------------------------------------------------------------
    // 동의 거부 (POST /oauth2/authorize, action=deny)
    // -------------------------------------------------------------------------

    /**
     * 거부 시 redirect_uri 로 error=access_denied 반환
     */
    @Test
    void submitConsent_deny_returnsAccessDenied() throws Exception {
        mockMvc.perform(post("/oauth2/authorize")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .param("action", "deny")
                        .with(csrf())
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", Matchers.startsWith(REDIRECT_URI)))
                .andExpect(header().string("Location", Matchers.containsString("error=access_denied")));
    }

//    /**
//     * 거부 시 state 가 있으면 Location 에 함께 포함된다
//     */
//    @Test
//    void submitConsent_deny_withState_includesStateInRedirect() throws Exception {
//        mockMvc.perform(post("/oauth2/authorize")
//                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
//                        .param("client_id", CLIENT_ID)
//                        .param("redirect_uri", REDIRECT_URI)
//                        .param("scope", "read")
//                        .param("state", "state-abc")
//                        .param("action", "deny")
//                        .with(user(USERNAME).roles("USER")))
//                .andExpect(status().isFound())
//                .andExpect(header().string("Location", Matchers.containsString("error=access_denied")))
//                .andExpect(header().string("Location", Matchers.containsString("state=state-abc")));
//    }

    /**
     * 거부 시 saveConsent() 는 호출되지 않는다
     */
    @Test
    void submitConsent_deny_doesNotSaveConsent() throws Exception {
        mockMvc.perform(post("/oauth2/authorize")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .param("action", "deny")
                        .with(user(USERNAME).roles("USER")));

        verify(consentService, never()).saveConsent(any(), any(), any());
    }
}