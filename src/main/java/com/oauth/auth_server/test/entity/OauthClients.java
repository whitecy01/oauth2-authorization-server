package com.oauth.auth_server.test.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth_clients")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClients {
    @Id
    @Column(name = "client_id", length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false, length = 200)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 100)
    private String clientName;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    public OauthClients(String clientId, String clientSecret, String clientName) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientName = clientName;
    }
}
