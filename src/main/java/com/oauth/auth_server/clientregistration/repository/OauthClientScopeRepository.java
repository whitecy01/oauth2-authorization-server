package com.oauth.auth_server.clientregistration.repository;

import com.oauth.auth_server.clientregistration.entity.OauthClientScope;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface OauthClientScopeRepository extends JpaRepository<OauthClientScope, Long> {
    List<OauthClientScope> findByClient_ClientId(String clientId);
}