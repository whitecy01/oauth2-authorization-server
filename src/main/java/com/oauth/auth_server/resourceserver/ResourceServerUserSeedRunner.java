package com.oauth.auth_server.resourceserver;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ResourceServerUserSeedRunner implements ApplicationRunner {

    private final ResourceServerUserRepository resourceServerUserRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (resourceServerUserRepository.findByUsername("user").isPresent()) {
            return;
        }

        resourceServerUserRepository.save(new ResourceServerUser(
                "user",
                "Test User",
                "user@example.com",
                "USER",
                "Platform",
                "010-1234-5678"
        ));
    }
}
