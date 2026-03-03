package com.oauth.auth_server.clientregistration.repository;


import com.oauth.auth_server.clientregistration.entity.OauthClientRedirectUri;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientRedirectUriRepository extends JpaRepository<OauthClientRedirectUri, Long> {
    List<OauthClientRedirectUri> findByClient_ClientId(String clientId);
}