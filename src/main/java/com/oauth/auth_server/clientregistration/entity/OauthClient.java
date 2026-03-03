package com.oauth.auth_server.clientregistration.entity;

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

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    public OauthClient(String clientId, String clientSecret, boolean active, String clientName) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.active = active;
        this.clientName = clientName;
    }
}
