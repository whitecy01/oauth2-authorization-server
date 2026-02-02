package com.oauth.auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(
        name = "oauth_client_scopes",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"client_id", "scope"})
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClientScopes {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long scopesId;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private OauthClients client;

    @Column(name = "scope", nullable = false, length = 100)
    private String scope;

    public OauthClientScopes(OauthClients client, String scope) {
        this.client = client;
        this.scope = scope;
    }
}