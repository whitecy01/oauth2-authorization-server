package com.oauth.auth_server.config.annotation.web.configurers;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 이 클래스는 Authorization Server 관련 설정(Configurer)들의 공통 기반 클래스
 * 더 정확하게 말하면 OAuth2 Authorization Server 전용 HTTPSecurity 확장 설정의 추상 베이스 클래스
 */
abstract class AbstractOAuth2Configurer {

    private final ObjectPostProcessor<Object> objectPostProcessor;

    AbstractOAuth2Configurer(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }

    abstract void init(HttpSecurity httpSecurity);

    abstract void configure(HttpSecurity httpSecurity);

    abstract RequestMatcher getRequestMatcher();

    protected final <T> T postProcess(T object) {
        return (T) this.objectPostProcessor.postProcess(object);
    }

    protected final ObjectPostProcessor<Object> getObjectPostProcessor() {
        return this.objectPostProcessor;
    }

}
