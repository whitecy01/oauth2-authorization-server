package com.oauth.auth_server.config.annotation.web.configurers;


import com.oauth.auth_server.InMemoryOAuth2AuthorizationConsentService;
import com.oauth.auth_server.InMemoryOAuth2AuthorizationService;
import com.oauth.auth_server.OAuth2AuthorizationConsentService;
import com.oauth.auth_server.OAuth2AuthorizationService;
import com.oauth.auth_server.client.RegisteredClientRepository;
import com.oauth.auth_server.settings.AuthorizationServerSettings;
import java.util.Map;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

final class OAuth2ConfigurerUtils {

    private OAuth2ConfigurerUtils() {
    }

    static String withMultipleIssuersPattern(String endpointUri) {
        Assert.hasText(endpointUri, "endpointUri cannot be empty");
        return endpointUri.startsWith("/") ? "/**" + endpointUri : "/**/" + endpointUri;
    }

    /**
     * RFC 6749의 client_id 기반 클라이언트 식별/검증에 필요한 저장소
     */
    static RegisteredClientRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
        RegisteredClientRepository registeredClientRepository = httpSecurity
                .getSharedObject(RegisteredClientRepository.class);
        if (registeredClientRepository == null) {
            registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository.class);
            httpSecurity.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }
        return registeredClientRepository;
    }

    /**
     * RFC 6749 Authorization Code 발급 후 서버가 code/authorization 상태를 저장해야 하니까 필요
     */
    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        OAuth2AuthorizationService authorizationService = httpSecurity
                .getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }
            httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }
        return authorizationService;
    }

    /**
     * RFC 6749 본문엔 “consent UI”가 표준화돼 있진 않지만, scope 동의 흐름을 구현하려면 서버 쪽에서 동의 상태 저장이 필요해서 SAS는 여기로 분리
     */
    static OAuth2AuthorizationConsentService getAuthorizationConsentService(HttpSecurity httpSecurity) {
        OAuth2AuthorizationConsentService authorizationConsentService = httpSecurity
                .getSharedObject(OAuth2AuthorizationConsentService.class);
        if (authorizationConsentService == null) {
            authorizationConsentService = getOptionalBean(httpSecurity, OAuth2AuthorizationConsentService.class);
            if (authorizationConsentService == null) {
                authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
            }
            httpSecurity.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
        }
        return authorizationConsentService;
    }

    /**
     *  /oauth2/authorize, /oauth2/token 같은 엔드포인트 URI 결정에 필요
     */
    static AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        AuthorizationServerSettings authorizationServerSettings = httpSecurity
                .getSharedObject(AuthorizationServerSettings.class);
        if (authorizationServerSettings == null) {
            authorizationServerSettings = getBean(httpSecurity, AuthorizationServerSettings.class);
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }
        return authorizationServerSettings;
    }

    static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
        return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
    }

    @SuppressWarnings("unchecked")
    static <T> T getBean(HttpSecurity httpSecurity, ResolvableType type) {
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
        String[] names = context.getBeanNamesForType(type);
        if (names.length == 1) {
            return (T) context.getBean(names[0]);
        }
        if (names.length > 1) {
            throw new NoUniqueBeanDefinitionException(type, names);
        }
        throw new NoSuchBeanDefinitionException(type);
    }

    /**
     * 위 기능들이 “sharedObject 없으면 Spring Bean에서 가져와 세팅”을 해야 하니 의존 메소드로 포함
     */
    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils
                .beansOfTypeIncludingAncestors(httpSecurity.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": "
                            + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }

    @SuppressWarnings("unchecked") // 컴파일러야 여기서 발생하는 unchecked 경고는 무시해줘라는 말
    static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
        String[] names = context.getBeanNamesForType(type);
        if (names.length > 1) {
            throw new NoUniqueBeanDefinitionException(type, names);
        }
        return (names.length == 1) ? (T) context.getBean(names[0]) : null;
    }


}
