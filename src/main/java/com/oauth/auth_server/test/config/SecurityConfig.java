package com.oauth.auth_server.test.config;

import com.oauth.auth_server.springauthserver.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 개발 초기에는 CSRF 끄는 게 테스트 편함(나중에 다시 켜도 됨)
                .csrf(csrf -> csrf.disable())

                // 인가 서버 엔드포인트는 인증 필요
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated()
                )

                // 기본 폼 로그인 페이지 사용
                .formLogin(Customizer.withDefaults())

                // 로그아웃도 기본 제공
                .logout(Customizer.withDefaults());

        http.addFilterAfter(new OAuth2AuthorizationEndpointFilter(),
                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}