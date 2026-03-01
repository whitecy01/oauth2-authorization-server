package com.oauth.auth_server.config.annotation.web.configurers;

import com.oauth.auth_server.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.oauth.auth_server.settings.AuthorizationServerSettings;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class OAuth2AuthorizationEndpointConfigurer extends AbstractOAuth2Configurer {

    private RequestMatcher requestMatcher;

    OAuth2AuthorizationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {

        // 1️⃣ AuthorizationServerSettings 검증
        /**
         * authorizationEndpointUri에  Authorization Server 설정 객체 가져오기 휴 설정에 정의된 인가 엔드포인트 경로 문자열 가져옴
         */
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
                .getAuthorizationServerSettings(httpSecurity);
        String authorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
                ? OAuth2ConfigurerUtils
                .withMultipleIssuersPattern(authorizationServerSettings.getAuthorizationEndpoint())
                : authorizationServerSettings.getAuthorizationEndpoint();

        /**
         * GET 또는 POST로 들어오는 /oauth2/authorize 요청만 이 Configurer/필터가 처리하도록 RequestMatcher를 구성하는 과정
         */
        this.requestMatcher = new OrRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, authorizationEndpointUri),
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, authorizationEndpointUri));

        /**
         * 기본 Provider 만들고, 사용자가 추가로 등록한 Provider가 있다면 앞쪽에 키워넣는 과정
         * 이 메서드는 보통 이런 Provider들을 만든다:
         * 	- OAuth2AuthorizationCodeRequestAuthenticationProvider
         * 	- OAuth2AuthorizationConsentAuthenticationProvider
         * 	- (OIDC 켜져있으면 OIDC 관련 Provider)
         * 	즉, 인가 엔드포인트에서 기본적으로 처리해야 하는 인증 로직들
         * 	createDefaultAuthenticationProviders는 기본 인가 처리 로직 생성
         * 	this.authenticationProviders 사용자 정의 Provider
         */
        List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
        if (!this.authenticationProviders.isEmpty()) {
            authenticationProviders.addAll(0, this.authenticationProviders);
        }

    }

    private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
                OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
                OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
                OAuth2ConfigurerUtils.getAuthorizationConsentService(httpSecurity));
        if (this.authorizationCodeRequestAuthenticationValidator != null) {
            authorizationCodeRequestAuthenticationProvider
                    .setAuthenticationValidator(new OAuth2AuthorizationCodeRequestAuthenticationValidator()
                            .andThen(this.authorizationCodeRequestAuthenticationValidator));
        }
        authenticationProviders.add(authorizationCodeRequestAuthenticationProvider);

        OAuth2AuthorizationConsentAuthenticationProvider authorizationConsentAuthenticationProvider = new OAuth2AuthorizationConsentAuthenticationProvider(
                OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
                OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
                OAuth2ConfigurerUtils.getAuthorizationConsentService(httpSecurity));
        authenticationProviders.add(authorizationConsentAuthenticationProvider);

        return authenticationProviders;
    }


    @Override
    void configure(HttpSecurity httpSecurity) {

    }

    @Override
    RequestMatcher getRequestMatcher() {
        return null;
    }


}


