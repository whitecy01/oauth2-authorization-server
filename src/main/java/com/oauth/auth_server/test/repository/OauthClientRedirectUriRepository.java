package com.oauth.auth_server.test.repository;

import com.oauth.auth_server.test.entity.OauthClientRedirectUri;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientRedirectUriRepository
        extends JpaRepository<OauthClientRedirectUri, Long> {
}