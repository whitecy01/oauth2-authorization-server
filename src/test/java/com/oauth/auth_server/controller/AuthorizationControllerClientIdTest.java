package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationException;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.oauth.auth_server.oauth2.core.OAuth2Error;
import com.oauth.auth_server.service.AuthorizationConsentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationEndpointFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AuthorizationController.class)
public class AuthorizationControllerClientIdTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    @MockitoBean
    private AuthorizationConsentService consentService;

    @MockitoBean
    private OAuth2AuthorizationEndpointFilter authorizationEndpointFilter;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    @Test
    void authorize_withClientId_returnInvalidRequest() throws Exception {
        // client_id="" 또는 " " → provider 가 redirect_uri 포함 예외를 던짐
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "client_id must not be blank", null),
                        REDIRECT_URI, "state-abc"));

        // client_id 파라미터 자체가 없는 경우 → Controller 가 400 직접 반환 (provider 호출 안 함)
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());

        // client_id="" → provider 예외 → redirect
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));

        // client_id=" " → provider 예외 → redirect
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", " ")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }
}