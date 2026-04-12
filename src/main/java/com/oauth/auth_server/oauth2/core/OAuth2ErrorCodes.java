package com.oauth.auth_server.oauth2.core;

import java.util.Map;

/**
 * RFC 6749 에러 코드 상수 및 에러 코드별 RFC URI 매핑.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 §5.2 Token Error Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1 Authorization Error Response</a>
 */
public final class OAuth2ErrorCodes {

    // 토큰 엔드포인트 (§5.2)
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_SCOPE = "invalid_scope";

    // 인가 엔드포인트 (§4.1.2.1)
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String ACCESS_DENIED = "access_denied";

    private static final String TOKEN_ERROR_URI =
            "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String AUTHORIZATION_ERROR_URI =
            "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private static final Map<String, String> ERROR_URI_MAP = Map.of(
            INVALID_REQUEST, TOKEN_ERROR_URI,
            INVALID_CLIENT, TOKEN_ERROR_URI,
            INVALID_GRANT, TOKEN_ERROR_URI,
            UNSUPPORTED_GRANT_TYPE, TOKEN_ERROR_URI,
            INVALID_SCOPE, TOKEN_ERROR_URI,
            UNSUPPORTED_RESPONSE_TYPE, AUTHORIZATION_ERROR_URI,
            ACCESS_DENIED, AUTHORIZATION_ERROR_URI
    );

    public static String getUri(String errorCode) {
        return ERROR_URI_MAP.get(errorCode);
    }

    private OAuth2ErrorCodes() {}
}