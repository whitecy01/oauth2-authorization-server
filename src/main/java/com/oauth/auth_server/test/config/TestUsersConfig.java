package com.oauth.auth_server.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class TestUsersConfig {

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1234") // 개발용. 나중에 BCrypt로 바꾸기
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
}