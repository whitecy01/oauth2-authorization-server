package com.oauth.auth_server.clientregistration.entity;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(
        name = "oauth_client_redirect_uris",
        uniqueConstraints = @UniqueConstraint(columnNames = {"client_id", "redirect_uri"})
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClientRedirectUri {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private OauthClient client;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "text")
    private String redirectUri;

    public OauthClientRedirectUri(OauthClient client, String redirectUri) {
        this.client = client;
        this.redirectUri = redirectUri;
    }
}