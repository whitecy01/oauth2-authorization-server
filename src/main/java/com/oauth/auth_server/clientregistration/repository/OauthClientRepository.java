package com.oauth.auth_server.clientregistration.repository;

import com.oauth.auth_server.clientregistration.entity.OauthClient;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientRepository extends JpaRepository<OauthClient, String> {
    Optional<OauthClient> findByClientIdAndActiveTrue(String clientId);
}