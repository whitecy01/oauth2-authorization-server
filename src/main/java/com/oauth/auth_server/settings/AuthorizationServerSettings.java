package com.oauth.auth_server.settings;

import java.util.Map;

public final class AuthorizationServerSettings extends AbstractSettings {
    private AuthorizationServerSettings(Map<String, Object> settings) {
        super(settings);
    }

    // (선택) Spring이 엔드포인트 URI 패턴 만들 때 사용
    public boolean isMultipleIssuersAllowed() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.MULTIPLE_ISSUERS_ALLOWED);
    }

    // ✅ RFC 6749 Authorization Endpoint (기본: /oauth2/authorize)
    public String getAuthorizationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT);
    }

    // ✅ RFC 6749 Token Endpoint (기본: /oauth2/token)
    public String getTokenEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT);
    }

    public static Builder builder() {
        return new Builder()
                .multipleIssuersAllowed(false)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token");
    }

    public static final class Builder extends AbstractBuilder<AuthorizationServerSettings, Builder> {

        private Builder() {}

        public Builder multipleIssuersAllowed(boolean multipleIssuersAllowed) {
            return setting(ConfigurationSettingNames.AuthorizationServer.MULTIPLE_ISSUERS_ALLOWED,
                    multipleIssuersAllowed);
        }

        public Builder authorizationEndpoint(String authorizationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
        }

        public Builder tokenEndpoint(String tokenEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT, tokenEndpoint);
        }

        @Override
        public AuthorizationServerSettings build() {
            return new AuthorizationServerSettings(getSettings());
        }
    }
}
