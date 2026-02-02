package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthClientScopes;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientScopesRepository extends JpaRepository<OauthClientScopes, Long> {

}