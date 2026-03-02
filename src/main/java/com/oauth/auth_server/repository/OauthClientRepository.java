package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthClient;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientRepository extends JpaRepository<OauthClient, String> {
    Optional<OauthClient> findByClientIdAndActiveTrue(String clientId);
}