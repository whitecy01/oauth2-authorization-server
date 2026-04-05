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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationEndpointFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - response_type 파라미터 검증 유닛 테스트
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerResponseTypeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    @MockitoBean
    private AuthorizationConsentService consentService;

    @MockitoBean
    private OAuth2AuthorizationEndpointFilter authorizationEndpointFilter;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    private static final RegisteredClient CLIENT = RegisteredClient.builder()
            .clientId("test-client").clientName("Test Client").clientSecret("secret")
            .redirectUri(REDIRECT_URI).scope("read").active(true).build();

    @Test
    void authorize_withResponseTypeCode_showsConsentPage() throws Exception {
        given(provider.process(any())).willThrow(new ConsentRequiredException(
                CLIENT, "user", List.of("read"),
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        "code", "test-client", REDIRECT_URI, List.of("read"), "state-abc", "user", 1)));

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
    void authorize_withoutResponseType_returnsInvalidRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "response_type is required", null),
                        REDIRECT_URI, "state-abc"));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }

    @Test
    void authorize_withUnsupportedResponseType_returnsUnsupportedResponseType() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("unsupported_response_type", "only response_type=code is supported", null),
                        REDIRECT_URI, "state-abc"));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "token")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=unsupported_response_type")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }
}