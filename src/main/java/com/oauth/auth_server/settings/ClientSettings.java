package com.oauth.auth_server.settings;

import java.io.Serial;
import java.util.Map;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;


/**
 * ClientSettings는 OAuth Client(RegisteredClient)의 “보안 동작 정책”을 담는 설정 객체다.
 * 대표적으로 이런 설정들이 있다:
 * 	- requireProofKey (PKCE 필수 여부)
 * 	- requireAuthorizationConsent (동의 화면 강제 여부)
 * 	- jwkSetUrl (클라이언트의 JWK 주소)
 * 	- tokenEndpointAuthenticationSigningAlgorithm
 * 	- x509CertificateSubjectDN
 */
public final class ClientSettings extends AbstractSettings {
    @Serial
    private static final long serialVersionUID = 9015034829752473931L;

    private ClientSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns {@code true} if authorization consent is required when the client requests
     * access. The default is {@code false}.
     * @return {@code true} if authorization consent is required when the client requests
     * access, {@code false} otherwise
     */
    public boolean isRequireAuthorizationConsent() {
        return getSetting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT);
    }

//    /**
//     * Constructs a new {@link Builder} with the default settings.
//     * @return the {@link Builder}
//     */
//    public static Builder builder() {
//        return new Builder().requireProofKey(false).requireAuthorizationConsent(false);
//    }

    /**
     * Constructs a new {@link Builder} with the provided settings.
     * @param settings the settings to initialize the builder
     * @return the {@link Builder}
     */
    public static Builder withSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        return new Builder().settings((s) -> s.putAll(settings));
    }

    /**
     * A builder for {@link ClientSettings}.
     */
    public static final class Builder extends AbstractBuilder<ClientSettings, Builder> {

        private Builder() {
        }

        /**
         * Set to {@code true} if authorization consent is required when the client
         * requests access. This applies to all interactive flows (e.g.
         * {@code authorization_code} and {@code device_code}).
         * @param requireAuthorizationConsent {@code true} if authorization consent is
         * required when the client requests access, {@code false} otherwise
         * @return the {@link Builder} for further configuration
         */
        public Builder requireAuthorizationConsent(boolean requireAuthorizationConsent) {
            return setting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT, requireAuthorizationConsent);
        }

        /**
         * Builds the {@link ClientSettings}.
         * @return the {@link ClientSettings}
         */
        @Override
        public ClientSettings build() {
            return new ClientSettings(getSettings());
        }

    }
}