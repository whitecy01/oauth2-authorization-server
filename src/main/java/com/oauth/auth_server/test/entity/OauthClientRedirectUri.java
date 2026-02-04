package com.oauth.auth_server.test.entity;

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
        name = "oauth_client_redirect_uris",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"client_id", "redirect_uri"})
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClientRedirectUri {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long redirectUrisId;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private OauthClients client;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "text")
    private String redirectUri;

    public OauthClientRedirectUri(OauthClients client, String redirectUri) {
        this.client = client;
        this.redirectUri = redirectUri;
    }
}
