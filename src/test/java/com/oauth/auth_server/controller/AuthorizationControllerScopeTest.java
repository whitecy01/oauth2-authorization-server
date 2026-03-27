package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.oauth.auth_server.oauth2.authorization.ConsentRequiredException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationToken;
import com.oauth.auth_server.oauth2.core.OAuth2Error;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - scope 파라미터 검증 유닛 테스트
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerScopeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    private static final RegisteredClient CLIENT = RegisteredClient.builder()
            .clientId("test-client").clientName("Test Client").clientSecret("secret")
            .redirectUri(REDIRECT_URI).scope("read").scope("write").active(true).build();

    private final ConsentRequiredException consentRequired = new ConsentRequiredException(
            CLIENT, "user", List.of("read"),
            new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    "code", "test-client", REDIRECT_URI, List.of("read"), "state-abc", "user", 1));

    @Test
    void authorize_withoutScope_proceeds() throws Exception {
        given(provider.process(any())).willThrow(consentRequired);
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void authorize_withSingleValidScope_proceeds() throws Exception {
        given(provider.process(any())).willThrow(consentRequired);
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void authorize_withMultipleValidScopes_proceeds() throws Exception {
        given(provider.process(any())).willThrow(consentRequired);
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read write")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void authorize_withDuplicateScopeParam_returnsInvalidScope() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_scope", "scope parameter must not be duplicated", null),
                        REDIRECT_URI, "state-abc"));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("scope", "write")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_scope")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }

    @Test
    void authorize_withUnregisteredScope_returnsInvalidScope() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_scope", "scope is not registered: admin", null),
                        REDIRECT_URI, "state-abc"));

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

    @Test
    void authorize_withMalformedScope_returnsInvalidScope() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_scope", "scope contains invalid characters", null),
                        REDIRECT_URI, "state-abc"));

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