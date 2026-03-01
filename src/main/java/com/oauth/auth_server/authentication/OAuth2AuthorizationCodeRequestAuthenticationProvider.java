package com.oauth.auth_server.authentication;

import com.oauth.auth_server.OAuth2Authorization;
import com.oauth.auth_server.OAuth2AuthorizationCode;
import com.oauth.auth_server.OAuth2AuthorizationConsentService;
import com.oauth.auth_server.OAuth2AuthorizationService;
import com.oauth.auth_server.OAuth2TokenType;
import com.oauth.auth_server.client.RegisteredClient;
import com.oauth.auth_server.client.RegisteredClientRepository;
import com.oauth.auth_server.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import java.security.Principal;
import java.util.Set;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * /oauth2/authorize 요청을 검증하고, Authorization Code를 생성하는 Provider다.
 * GET /oauth2/authorize
 *     ?response_type=code
 *     &client_id=...
 *     &redirect_uri=...
 *     &scope=...
 *     &state=...
 * 이 요청이 들어오면
 * AuthorizationEndpointFilter
 *     ↓
 * authenticationManager.authenticate()
 *     ↓
 * OAuth2AuthorizationCodeRequestAuthenticationProvider.authenticate()
 * 이 클래스 생성됨
 * 이 Provider가 하는 일
 * 1. client_id 검증 == RegisteredClientRepository에서 client 조회
 * 	- 존재하는 클라이언트인가?
 * 	- 해당 grant_type 허용하는가?
 * 2. redirect_uri 거증 -> 등록한 redirect URI와 일치하는가?
 * 3. scope 검증 -> 요청 scope가 허용된 scope인가
 * 4. 사용자 동의 필요 여부 판단 -> OAuth2AuthorizationConsentService == 이전에 승인된 scope인가?, 새 scope인가
 * 5. Authorization Code 생성 -> new OAuth2AuthorizationCode(...)
 * 6. OAuth2Authorization 생성 후 저장 -> OAuth2AuthorizationService.save(...) == 여기서 코드 상태 저장됨.
 * 7. 성공 Authentication 반환 성공하면 OAuth2AuthorizationCodeRequestAuthenticationToken == 인증 완료된 객체 반환
 *
 * 	•	4.1.1 Authorization Request
 * 	•	4.1.2 Authorization Response
 * 	•	4.1.2.1 Error Response
 * 	•	3.1.2 Redirect URI
 * 	•	3.3 Scope
 * 	•	5.2 Error Response
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator =
            new OAuth2AuthorizationCodeGenerator();

    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
            new OAuth2AuthorizationCodeRequestAuthenticationValidator();

    public OAuth2AuthorizationCodeRequestAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService // (원본 시그니처 유지용, RFC 핵심에는 직접 안 씀)
    ) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        // 1) client_id -> RegisteredClient 조회 (RFC 6749 §4.1.1)
        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(authorizationCodeRequestAuthentication.getClientId());
        if (registeredClient == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
                    authorizationCodeRequestAuthentication, null);
        }

        OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder =
                OAuth2AuthorizationCodeRequestAuthenticationContext
                        .with(authorizationCodeRequestAuthentication)
                        .registeredClient(registeredClient);

        OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext =
                authenticationContextBuilder.build();

        // 2) grant_type(=authorization_code) / response_type=code 성격 검증 (RFC 6749 §4.1.1)
        OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_AUTHORIZATION_GRANT_TYPE_VALIDATOR
                .accept(authenticationContext);

        // 3) redirect_uri, scope 등 요청 파라미터 검증 (RFC 6749 §3.1.2, §3.3, §4.1.1)
        this.authenticationValidator.accept(authenticationContext);

        // 4) 리소스 오너(사용자) 인증 확인 (RFC 6749 §4.1.1)
        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            // 로그인 안 된 상태면 “요청은 유효하지만 아직 인증 전” 상태로 그대로 반환
            return authorizationCodeRequestAuthentication;
        }

        // 5) Authorization Request 객체 구성 (RFC 6749 §4.1.1)
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
                .clientId(registeredClient.getClientId())
                .redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
                .scopes(authorizationCodeRequestAuthentication.getScopes())
                .state(authorizationCodeRequestAuthentication.getState())
                .additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
                .build();

        // 6) Authorization Code 생성 (RFC 6749 §4.1.2)
        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
                authorizationCodeRequestAuthentication,
                registeredClient,
                null,
                authorizationRequest.getScopes()
        );

        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the authorization code.", ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        // 7) 서버에 Authorization 상태 저장 (코드/요청/사용자 연결)
        OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                .authorizedScopes(authorizationRequest.getScopes())
                .token(authorizationCode)
                .build();

        this.authorizationService.save(authorization);

        // 8) redirect_uri 결정 (RFC 6749 §3.1.2 / §4.1.2)
        String redirectUri = authorizationRequest.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }

        // 9) 성공 결과 반환 (Filter의 success handler가 redirect에 code/state 실어 보냄)
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                authorizationRequest.getAuthorizationUri(),
                registeredClient.getClientId(),
                principal,
                authorizationCode,
                redirectUri,
                authorizationRequest.getState(),
                authorizationRequest.getScopes()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
        Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
        this.authorizationCodeGenerator = authorizationCodeGenerator;
    }

    public void setAuthenticationValidator(
            Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator
    ) {
        Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
        this.authenticationValidator = authenticationValidator;
    }

    private static OAuth2Authorization.Builder authorizationBuilder(
            RegisteredClient registeredClient,
            Authentication principal,
            OAuth2AuthorizationRequest authorizationRequest
    ) {
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
    }

    private static OAuth2TokenContext createAuthorizationCodeTokenContext(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredClient registeredClient,
            OAuth2Authorization authorization,
            Set<String> authorizedScopes
    ) {
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationCodeRequestAuthentication);

        if (authorization != null) {
            tokenContextBuilder.authorization(authorization);
        }

        return tokenContextBuilder.build();
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null
                && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
                && principal.isAuthenticated();
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredClient registeredClient
    ) {
        throwError(errorCode, parameterName, ERROR_URI,
                authorizationCodeRequestAuthentication, registeredClient, null);
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            String errorUri,
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredClient registeredClient,
            OAuth2AuthorizationRequest authorizationRequest
    ) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throwError(error, parameterName,
                authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
    }

    private static void throwError(
            OAuth2Error error,
            String parameterName,
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredClient registeredClient,
            OAuth2AuthorizationRequest authorizationRequest
    ) {
        String redirectUri = resolveRedirectUri(authorizationCodeRequestAuthentication, authorizationRequest, registeredClient);

        // RFC 6749 권고: client_id/state 오류 등 일부는 redirect 막고 바로 에러 처리 (원본 로직 유지)
        if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
                && (parameterName.equals(OAuth2ParameterNames.CLIENT_ID)
                || parameterName.equals(OAuth2ParameterNames.STATE))) {
            redirectUri = null;
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken result =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        authorizationCodeRequestAuthentication.getAuthorizationUri(),
                        authorizationCodeRequestAuthentication.getClientId(),
                        (Authentication) authorizationCodeRequestAuthentication.getPrincipal(),
                        redirectUri,
                        authorizationCodeRequestAuthentication.getState(),
                        authorizationCodeRequestAuthentication.getScopes(),
                        authorizationCodeRequestAuthentication.getAdditionalParameters()
                );

        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, result);
    }

    private static String resolveRedirectUri(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            OAuth2AuthorizationRequest authorizationRequest,
            RegisteredClient registeredClient
    ) {
        if (authorizationCodeRequestAuthentication != null
                && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            return authorizationCodeRequestAuthentication.getRedirectUri();
        }
        if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredClient != null) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }

}