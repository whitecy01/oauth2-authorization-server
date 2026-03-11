package com.oauth.auth_server.resourceserver;

import com.oauth.auth_server.entity.OauthAccessToken;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ResourceServerService {

    private final OauthAccessTokenRepository accessTokenRepository;
    private final ResourceServerUserRepository resourceServerUserRepository;

    public ResourceServerUserProfile getUserProfile(String bearerToken) {
        OauthAccessToken accessToken = accessTokenRepository.findByToken(bearerToken)
                .orElseThrow(() -> new IllegalArgumentException("access token is invalid"));

        if (accessToken.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("access token is expired");
        }

        ResourceServerUser user = resourceServerUserRepository.findByUsername(accessToken.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("user info not found"));

        return new ResourceServerUserProfile(
                user.getUsername(),
                user.getName(),
                user.getEmail(),
                user.getRole(),
                user.getDepartment(),
                user.getPhoneNumber()
        );
    }
}
