package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthClientRedirectUri;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientRedirectUriRepository
        extends JpaRepository<OauthClientRedirectUri, Long> {
}