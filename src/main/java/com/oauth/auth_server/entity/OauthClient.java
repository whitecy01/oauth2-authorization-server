package com.oauth.auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth_clients")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClient {

    @Id
    @Column(name = "client_id", length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false, length = 200)
    private String clientSecret;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "text")
    private String redirectUri;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    public OauthClient(String clientId, String clientSecret, String redirectUri) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }
}