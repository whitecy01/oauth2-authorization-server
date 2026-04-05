package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.oauth2.authorization.AuthorizationCodeIssuedToken;
import com.oauth.auth_server.oauth2.authorization.ConsentRequiredException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationToken;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationEndpointFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - consent 흐름 유닛 테스트
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerConsentTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    @MockitoBean
    private AuthorizationConsentService consentService;

    @MockitoBean
    private OAuth2AuthorizationEndpointFilter authorizationEndpointFilter;

    private static final String CLIENT_ID    = "test-client";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String USERNAME     = "user";

    private static final RegisteredClient CLIENT = RegisteredClient.builder()
            .clientId(CLIENT_ID).clientName("Test Client").clientSecret("secret")
            .redirectUri(REDIRECT_URI).scope("read").scope("write").active(true).build();

    @BeforeEach
    void setUp() {
        given(provider.issueCode(any(), any(), any(), any(), any()))
                .willReturn(new AuthorizationCodeIssuedToken("code123", REDIRECT_URI, "state-abc"));
    }

    // -------------------------------------------------------------------------
    // 동의 필요 여부 판단 (GET /oauth2/authorize)
    // -------------------------------------------------------------------------

    @Test
    void authorize_withNoExistingConsent_showsConsentPage() throws Exception {
        given(provider.process(any())).willThrow(new ConsentRequiredException(
                CLIENT, USERNAME, List.of("read"),
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        "code", CLIENT_ID, REDIRECT_URI, List.of("read"), "state-abc", USERNAME, 1)));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void authorize_withExistingConsent_issuesCodeDirectly() throws Exception {
        given(provider.process(any()))
                .willReturn(new AuthorizationCodeIssuedToken("code123", REDIRECT_URI, "state-abc"));

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

    @Test
    void authorize_withNewScopeNotYetConsented_showsConsentPage() throws Exception {
        given(provider.process(any())).willThrow(new ConsentRequiredException(
                CLIENT, USERNAME, List.of("read", "write"),
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        "code", CLIENT_ID, REDIRECT_URI, List.of("read", "write"), "state-abc", USERNAME, 1)));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read write")
                        .param("state", "state-abc")
                        .with(user(USERNAME).roles("USER")))
                .andExpect(status().isOk());
    }

    // -------------------------------------------------------------------------
    // 동의 승인 (POST /oauth2/authorize, action=approve)
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // 동의 거부 (POST /oauth2/authorize, action=deny)
    // -------------------------------------------------------------------------

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