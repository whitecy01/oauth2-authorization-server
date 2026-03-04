package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthAuthorizationConsent;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthAuthorizationConsentRepository extends JpaRepository<OauthAuthorizationConsent, Long> {
    List<OauthAuthorizationConsent> findByUsernameAndClientId(String username, String clientId);
}
