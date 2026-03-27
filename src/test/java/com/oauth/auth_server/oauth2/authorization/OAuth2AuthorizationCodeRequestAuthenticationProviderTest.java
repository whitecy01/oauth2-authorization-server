package com.oauth.auth_server.oauth2.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.oauth2.service.OAuth2AuthorizationService;
import com.oauth.auth_server.oauth2.service.RegisteredClientRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OAuth2AuthorizationCodeRequestAuthenticationProviderTest {

    private final RegisteredClientRepository clientRepository = mock(RegisteredClientRepository.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    private final AuthorizationConsentService consentService = mock(AuthorizationConsentService.class);

    private final OAuth2AuthorizationCodeRequestAuthenticationProvider provider =
            new OAuth2AuthorizationCodeRequestAuthenticationProvider(
                    clientRepository, authorizationService, consentService);

    private static final String CLIENT_ID = "client-id";
    private static final String REDIRECT_URI = "http://localhost/callback";

    private RegisteredClient defaultClient() {
        return RegisteredClient.builder()
                .clientId(CLIENT_ID)
                .clientSecret("secret")
                .redirectUri(REDIRECT_URI)
                .scope("read")
                .active(true)
                .build();
    }

    private OAuth2AuthorizationCodeRequestAuthenticationToken token(
            String responseType, String clientId, String redirectUri, List<String> scopes) {
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                responseType, clientId, redirectUri, scopes, "state-123", "user", scopes.isEmpty() ? 0 : 1);
    }

    @BeforeEach
    void setUp() {
        given(clientRepository.findByClientId(CLIENT_ID)).willReturn(Optional.of(defaultClient()));
    }

    @Test
    void process_withConsentAlreadyGiven_returnsIssuedToken() {
        given(consentService.hasConsent("user", CLIENT_ID, List.of("read"))).willReturn(true);

        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("code", CLIENT_ID, REDIRECT_URI, List.of("read"));

        AuthorizationCodeIssuedToken result = provider.process(request);

        assertThat(result.getCode()).isNotBlank();
        assertThat(result.getRedirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(result.getState()).isEqualTo("state-123");
        then(authorizationService).should().saveAuthorizationCode(any(), any(), any(), any(), any(), any());
    }

    @Test
    void process_withoutConsent_throwsConsentRequiredException() {
        given(consentService.hasConsent("user", CLIENT_ID, List.of("read"))).willReturn(false);

        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("code", CLIENT_ID, REDIRECT_URI, List.of("read"));

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(ConsentRequiredException.class)
                .satisfies(ex -> {
                    ConsentRequiredException e = (ConsentRequiredException) ex;
                    assertThat(e.getRegisteredClient().getClientId()).isEqualTo(CLIENT_ID);
                    assertThat(e.getRequestedScopes()).containsExactly("read");
                });
    }

    @Test
    void process_withInvalidResponseType_throwsOAuth2AuthorizationException() {
        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("token", CLIENT_ID, REDIRECT_URI, List.of("read"));

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthorizationException) ex).getError().getErrorCode())
                        .isEqualTo("unsupported_response_type"));
    }

    @Test
    void process_withUnregisteredClient_throwsOAuth2AuthorizationException() {
        given(clientRepository.findByClientId("unknown")).willReturn(Optional.empty());

        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("code", "unknown", REDIRECT_URI, List.of("read"));

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthorizationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_client"));
    }

    @Test
    void process_withUnregisteredRedirectUri_throwsOAuth2AuthorizationException() {
        given(consentService.hasConsent(any(), any(), any())).willReturn(true);

        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("code", CLIENT_ID, "http://evil.com/callback", List.of("read"));

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthorizationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_request"));
    }

    @Test
    void process_withUnregisteredScope_throwsOAuth2AuthorizationException() {
        given(consentService.hasConsent(any(), any(), any())).willReturn(true);

        OAuth2AuthorizationCodeRequestAuthenticationToken request =
                token("code", CLIENT_ID, REDIRECT_URI, List.of("admin"));

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthorizationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_scope"));
    }
}
