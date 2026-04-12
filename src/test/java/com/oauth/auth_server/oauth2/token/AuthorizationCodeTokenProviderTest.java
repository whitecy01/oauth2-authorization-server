package com.oauth.auth_server.oauth2.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.oauth2.core.OAuth2AccessToken;
import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.oauth2.service.OAuth2AuthorizationService;
import com.oauth.auth_server.oauth2.service.RegisteredClientRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthorizationCodeTokenProviderTest {

    private final RegisteredClientRepository clientRepository = mock(RegisteredClientRepository.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    private final ClientCredentialsExtractor credentialsExtractor = mock(ClientCredentialsExtractor.class);

    private final AuthorizationCodeTokenProvider provider = new AuthorizationCodeTokenProvider(
            clientRepository, authorizationService, credentialsExtractor);

    private static final String CLIENT_ID = "client1";
    private static final String CLIENT_SECRET = "secret1";
    private static final String REDIRECT_URI = "http://localhost/callback";
    private static final String CODE = "auth-code-123";

    private RegisteredClient defaultClient() {
        return RegisteredClient.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .redirectUri(REDIRECT_URI)
                .active(true)
                .build();
    }

    private OauthAuthorizationCode validCode() {
        return new OauthAuthorizationCode(CODE, CLIENT_ID, "user1", REDIRECT_URI, null,
                Instant.now(), Instant.now().plusSeconds(600));
    }

    private AuthorizationCodeTokenRequest validRequest() {
        return new AuthorizationCodeTokenRequest(
                List.of("authorization_code"),
                List.of(CODE),
                List.of(REDIRECT_URI),
                null, null, null
        );
    }

    @BeforeEach
    void setUp() {
        given(credentialsExtractor.extract(any(), any(), any()))
                .willReturn(Optional.of(new ClientCredentials(CLIENT_ID, CLIENT_SECRET)));
        given(clientRepository.findByClientId(CLIENT_ID))
                .willReturn(Optional.of(defaultClient()));
        given(authorizationService.findByCode(CODE))
                .willReturn(Optional.of(validCode()));
        given(authorizationService.saveAccessToken(any(), any(), any(), any()))
                .willReturn(new OAuth2AccessToken("token-value", Instant.now(), Instant.now().plusSeconds(3600)));
    }

    // ── 성공 ──────────────────────────────────────────────────────────────────

    @Test
    void 정상_요청이면_access_token을_반환한다() {
        OAuth2AccessToken result = provider.process(validRequest());

        assertThat(result.getTokenValue()).isEqualTo("token-value");
        then(authorizationService).should().deleteByCode(CODE);
    }

    // ── grant_type 검증 ───────────────────────────────────────────────────────

    @Test
    void grant_type이_없으면_invalid_request() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                null, List.of(CODE), List.of(REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_request"));
    }

    @Test
    void grant_type이_중복이면_invalid_request() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code", "authorization_code"),
                List.of(CODE), List.of(REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_request"));
    }

    @Test
    void grant_type이_authorization_code가_아니면_unsupported_grant_type() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("client_credentials"),
                List.of(CODE), List.of(REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("unsupported_grant_type"));
    }

    // ── code 검증 ─────────────────────────────────────────────────────────────

    @Test
    void code가_없으면_invalid_request() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code"), null, List.of(REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_request"));
    }

    @Test
    void code가_중복이면_invalid_request() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code"),
                List.of(CODE, CODE),
                List.of(REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_request"));
    }

    // ── redirect_uri 검증 ─────────────────────────────────────────────────────

    @Test
    void redirect_uri가_없으면_invalid_grant() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code"), List.of(CODE), null, null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));
    }

    @Test
    void redirect_uri가_중복이면_invalid_request() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code"), List.of(CODE),
                List.of(REDIRECT_URI, REDIRECT_URI), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_request"));
    }

    // ── 클라이언트 인증 ────────────────────────────────────────────────────────

    @Test
    void 클라이언트_자격증명_추출_실패시_invalid_client() {
        given(credentialsExtractor.extract(any(), any(), any())).willReturn(Optional.empty());

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_client"));
    }

    @Test
    void 클라이언트가_존재하지_않으면_invalid_client() {
        given(clientRepository.findByClientId(CLIENT_ID)).willReturn(Optional.empty());

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_client"));
    }

    @Test
    void 클라이언트_secret이_다르면_invalid_client() {
        given(credentialsExtractor.extract(any(), any(), any()))
                .willReturn(Optional.of(new ClientCredentials(CLIENT_ID, "wrong-secret")));

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_client"));
    }

    // ── redirect_uri 등록 여부 ────────────────────────────────────────────────

    @Test
    void 등록되지_않은_redirect_uri면_invalid_grant() {
        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                List.of("authorization_code"), List.of(CODE),
                List.of("http://evil.com/callback"), null, null, null);

        assertThatThrownBy(() -> provider.process(request))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));
    }

    // ── authorization code 검증 ───────────────────────────────────────────────

    @Test
    void 존재하지_않는_code면_invalid_grant() {
        given(authorizationService.findByCode(CODE)).willReturn(Optional.empty());

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));
    }

    @Test
    void 만료된_code면_삭제_후_invalid_grant() {
        OauthAuthorizationCode expired = new OauthAuthorizationCode(
                CODE, CLIENT_ID, "user1", REDIRECT_URI, null,
                Instant.now().minusSeconds(700), Instant.now().minusSeconds(1));
        given(authorizationService.findByCode(CODE)).willReturn(Optional.of(expired));

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));

        then(authorizationService).should().deleteByCode(CODE);
    }

    @Test
    void code의_clientId가_다르면_invalid_grant() {
        OauthAuthorizationCode wrongClient = new OauthAuthorizationCode(
                CODE, "other-client", "user1", REDIRECT_URI, null,
                Instant.now(), Instant.now().plusSeconds(600));
        given(authorizationService.findByCode(CODE)).willReturn(Optional.of(wrongClient));

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));
    }

    @Test
    void code의_redirect_uri가_다르면_invalid_grant() {
        OauthAuthorizationCode wrongUri = new OauthAuthorizationCode(
                CODE, CLIENT_ID, "user1", "http://other.com/callback", null,
                Instant.now(), Instant.now().plusSeconds(600));
        given(authorizationService.findByCode(CODE)).willReturn(Optional.of(wrongUri));

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));

        then(authorizationService).should(never()).saveAccessToken(any(), any(), any(), any());
    }

    @Test
    void 이미_사용된_code면_invalid_grant() {
        // 첫 번째 사용: 성공 후 deleteByCode 호출됨
        provider.process(validRequest());

        // 두 번째 사용: findByCode가 empty 반환 (이미 삭제됨)
        given(authorizationService.findByCode(CODE)).willReturn(Optional.empty());

        assertThatThrownBy(() -> provider.process(validRequest()))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> assertThat(errorCode(ex)).isEqualTo("invalid_grant"));
    }

    private String errorCode(Throwable ex) {
        return ((OAuth2AuthorizationException) ex).getError().getErrorCode();
    }
}
