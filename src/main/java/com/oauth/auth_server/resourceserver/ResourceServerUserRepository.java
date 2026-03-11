package com.oauth.auth_server.resourceserver;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResourceServerUserRepository extends JpaRepository<ResourceServerUser, Long> {
    Optional<ResourceServerUser> findByUsername(String username);
}
