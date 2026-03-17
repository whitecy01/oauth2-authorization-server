package com.oauth.auth_server.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import com.oauth.auth_server.clientregistration.repository.OauthClientRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * AuthorizationController - response_type 파라미터 검증 유닛 테스트
 *
 * RFC 6749 4.1.1 / 4.1.2.1 기준:
 * - response_type 은 REQUIRED
 * - 지원하지 않는 response_type 은 unsupported_response_type 에러
 */
@WebMvcTest(AuthorizationController.class)
class AuthorizationControllerResponseTypeTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OauthClientRepository clientRepository;

    @MockitoBean
    private OauthAuthorizationCodeRepository codeRepository;

    @MockitoBean
    private AuthorizationConsentService consentService;

    private static final String REDIRECT_URI = "http://localhost:8080/callback";

    /**
     * response_type=code 는 유일하게 지원하는 정상 값이다.
     * 검증을 통과해 동의 화면(200 OK)이 반환되어야 한다.
     */
    @Test
    void authorize_withResponseTypeCode_showsConsentPage() throws Exception {
        OauthClient client = new OauthClient("test-client", "secret", true, "Test Client");
        when(clientRepository.findByClientIdAndActiveTrue("test-client")).thenReturn(Optional.of(client));
        when(consentService.hasConsent(any(), any(), any())).thenReturn(false);

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
     * response_type 파라미터가 아예 없으면 invalid_request 에러를 반환해야 한다.
     * response_type에 값이 없을 때, 빈 문자열, 매개변수 2개 이상 invalid_request 에러를 반환해야 한다.
     * RFC 6749 §4.1.2.1: response_type is REQUIRED
     *
     * 기대 응답: 302 redirect → redirect_uri?error=invalid_request&state=state-abc
     */
    @Test
    void authorize_withoutResponseType_returnsInvalidRequest() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
        // response_type=
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "")
                        .param("client_id", "")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
        //response_type=" "
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", " ")
                        .param("client_id", " ")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "read")
                        .param("state", "state-abc")
                        .with(user("user").roles("USER")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern(REDIRECT_URI + "?error=invalid_request*"))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("state=state-abc")));
    }

    /**
     * 지원하지 않는 response_type(token, code id_token 등)은 거부해야 한다.
     * RFC 6749 §4.1.2.1: unsupported_response_type
     *
     * 기대 응답: 302 redirect → redirect_uri?error=unsupported_response_type&state=state-abc
     */
    @Test
    void authorize_withUnsupportedResponseType_returnsUnsupportedResponseType() throws Exception {
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
