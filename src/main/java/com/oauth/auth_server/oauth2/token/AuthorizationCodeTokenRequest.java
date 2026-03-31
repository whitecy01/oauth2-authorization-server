package com.oauth.auth_server.oauth2.token;

import java.util.List;

public class AuthorizationCodeTokenRequest {

    private final String grantType;
    private final String code;
    private final String redirectUri;
    private final String clientId;
    private final String clientSecret;
    private final String authorizationHeader;
    private final int grantTypeParamCount;
    private final int codeParamCount;
    private final int redirectUriParamCount;

    public AuthorizationCodeTokenRequest(
            List<String> grantTypes,
            List<String> codes,
            List<String> redirectUris,
            String clientId,
            String clientSecret,
            String authorizationHeader
    ) {
        this.grantTypeParamCount = grantTypes == null ? 0 : grantTypes.size();
        this.codeParamCount = codes == null ? 0 : codes.size();
        this.redirectUriParamCount = redirectUris == null ? 0 : redirectUris.size();

        this.grantType = (grantTypes != null && grantTypes.size() == 1) ? grantTypes.get(0) : null;
        this.code = (codes != null && codes.size() == 1) ? codes.get(0) : null;
        this.redirectUri = (redirectUris != null && redirectUris.size() == 1) ? redirectUris.get(0) : null;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authorizationHeader = authorizationHeader;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getAuthorizationHeader() {
        return authorizationHeader;
    }

    public int getGrantTypeParamCount() {
        return grantTypeParamCount;
    }

    public int getCodeParamCount() {
        return codeParamCount;
    }

    public int getRedirectUriParamCount() {
        return redirectUriParamCount;
    }
}
