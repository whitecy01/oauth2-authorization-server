package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - redirect_uri 파라미터 검증 유닛 테스트
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerRedirectUriTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private static final String REGISTERED_URI_1 = "http://localhost:8080/callback";
    private static final String REGISTERED_URI_2 = "http://localhost:8080/callback2";

    private static final RegisteredClient CLIENT = RegisteredClient.builder()
            .clientId("test-client").clientName("Test Client").clientSecret("secret")
            .redirectUri(REGISTERED_URI_1).scope("read").active(true).build();

    @Test
    void authorize_withoutRedirectUri_singleRegistered_proceeds() throws Exception {
        given(provider.process(any())).willThrow(new ConsentRequiredException(
                CLIENT, "user", List.of("read"),
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        "code", "test-client", null, List.of("read"), "state-abc", "user", 1)));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void authorize_withoutRedirectUri_multipleRegistered_returnsBadRequest() throws Exception {
        // redirect_uri 없고 등록된 URI 여러 개 → provider 가 redirectUri=null 예외 → 400
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "redirect_uri is required", null),
                        null, null));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorize_withBlankRedirectUri_returnsBadRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "redirect_uri must not be blank", null),
                        null, null));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorize_withFragmentInRedirectUri_returnsBadRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "redirect_uri must not contain a fragment", null),
                        null, null));

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REGISTERED_URI_1 + "#section")
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorize_withUnregisteredRedirectUri_returnsBadRequest() throws Exception {
        given(provider.process(any())).willThrow(
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "redirect_uri is not registered", null),
                        null, null));

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