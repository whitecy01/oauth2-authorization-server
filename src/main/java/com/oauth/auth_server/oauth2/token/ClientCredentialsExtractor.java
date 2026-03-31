package com.oauth.auth_server.oauth2.token;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class ClientCredentialsExtractor {

    public Optional<ClientCredentials> extract(String authorizationHeader, String clientId, String clientSecret) {
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Basic ")) {
            return extractFromBasicHeader(authorizationHeader);
        }
        return extractFromFormParams(clientId, clientSecret);
    }

    private Optional<ClientCredentials> extractFromBasicHeader(String authorizationHeader) {
        try {
            String encoded = authorizationHeader.substring(6).trim();
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int delimiterIndex = decoded.indexOf(':');
            if (delimiterIndex < 0) {
                return Optional.empty();
            }
            return Optional.of(new ClientCredentials(
                    decoded.substring(0, delimiterIndex),
                    decoded.substring(delimiterIndex + 1)
            ));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private Optional<ClientCredentials> extractFromFormParams(String clientId, String clientSecret) {
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            return Optional.empty();
        }
        return Optional.of(new ClientCredentials(clientId, clientSecret));
    }
}
