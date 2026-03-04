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
@Table(name = "oauth_access_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthAccessToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 200)
    private String token;

    @Column(nullable = false, length = 100)
    private String clientId;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(nullable = false)
    private Instant expiresAt;

    public OauthAccessToken(String token, String clientId, String username, Instant expiresAt) {
        this.token = token;
        this.clientId = clientId;
        this.username = username;
        this.expiresAt = expiresAt;
    }
}
