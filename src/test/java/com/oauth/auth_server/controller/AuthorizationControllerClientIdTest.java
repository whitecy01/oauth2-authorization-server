package com.oauth.auth_server.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AuthorizationController.class)
public class AuthorizationControllerClientIdTest {
    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OauthClientRepository clientRepository;

    @MockitoBean
    private OauthAuthorizationCodeRepository codeRepository;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    @Test
    void authorize_withClientId_returnInvalidRequest() throws Exception{
        // 값이 없는 경우
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isBadRequest());
        // " " 인 경우
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


        // 값이 2개 오는 경우
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
