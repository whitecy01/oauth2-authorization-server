package com.oauth.auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(
        name = "oauth_authorization_consents",
        uniqueConstraints = @UniqueConstraint(columnNames = {"client_id", "username", "scope"})
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthAuthorizationConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "username", nullable = false, length = 100)
    private String username;

    @Column(name = "scope", nullable = false, length = 100)
    private String scope;

    public OauthAuthorizationConsent(String clientId, String username, String scope) {
        this.clientId = clientId;
        this.username = username;
        this.scope = scope;
    }
}
