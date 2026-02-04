package com.oauth.auth_server.test.repository;

import com.oauth.auth_server.test.entity.OauthClientScopes;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientScopesRepository extends JpaRepository<OauthClientScopes, Long> {

}