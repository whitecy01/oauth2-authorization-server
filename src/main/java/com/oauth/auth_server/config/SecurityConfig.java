package com.oauth.auth_server.config;

import com.oauth.auth_server.oauth2.authorization.OAuth2AuthorizationEndpointFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
            OAuth2AuthorizationEndpointFilter authorizationEndpointFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/error", "/admin/**", "/oauth2/token", "/oauth2/token-page", "/resource/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .logout(Customizer.withDefaults())
                .addFilterAfter(authorizationEndpointFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    FilterRegistrationBean<OAuth2AuthorizationEndpointFilter> authorizationEndpointFilterRegistration(
            OAuth2AuthorizationEndpointFilter filter) {
        FilterRegistrationBean<OAuth2AuthorizationEndpointFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1234") // 개발용. 나중에 BCrypt로 바꾸기
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
}
