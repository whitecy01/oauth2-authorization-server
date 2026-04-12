package com.oauth.auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth_authorization_codes")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthAuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 200)
    private String code;

    @Column(nullable = false, length = 100)
    private String clientId;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(nullable = false, columnDefinition = "text")
    private String redirectUri;

    @Column(nullable = false)
    private Instant issuedAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(columnDefinition = "text")
    private String state;

    public OauthAuthorizationCode(String code, String clientId, String username,
                                  String redirectUri, String state, Instant issuedAt, Instant expiresAt) {
        this.code = code;
        this.clientId = clientId;
        this.username = username;
        this.redirectUri = redirectUri;
        this.state = state;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }
}