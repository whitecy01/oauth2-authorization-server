package com.oauth.auth_server.clientregistration.entity;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(
        name = "oauth_client_scopes",
        uniqueConstraints = @UniqueConstraint(columnNames = {"client_id", "scope"})
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthClientScope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OauthClient client;

    @Column(name = "scope", nullable = false, length = 100)
    private String scope;

    public OauthClientScope(OauthClient client, String scope) {
        this.client = client;
        this.scope = scope;
    }
}