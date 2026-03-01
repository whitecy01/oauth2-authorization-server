package com.oauth.auth_server;

import java.io.Serial;
import java.io.Serializable;
import org.springframework.util.Assert;

/**
 * OAuth2TokenType는 “이 토큰이 어떤 종류인가?”를 표현하는 타입 객체다.
 * RFC 6749 기준으로 토큰은 크게 access_token, refresh_token 두 종류가 있다.
 *
 * Spring Authorzation Server 내부에서는 문자열 access_token을 그대로 쓰지 않고
 * OAuth2TokenType.ACCESS_TOKEN
 * OAuth2TokenType.REFRESH_TOKEN
 * 이렇게 타입 객체로 감싼다.
 */

public final class OAuth2TokenType implements Serializable {

    @Serial
    private static final long serialVersionUID = -9015673781220922768L;

    /**
     * {@code access_token} token type.
     */
    public static final OAuth2TokenType ACCESS_TOKEN = new OAuth2TokenType("access_token");

    /**
     * {@code refresh_token} token type.
     */
    public static final OAuth2TokenType REFRESH_TOKEN = new OAuth2TokenType("refresh_token");

    private final String value;

    /**
     * Constructs an {@code OAuth2TokenType} using the provided value.
     * @param value the value of the token type
     */
    public OAuth2TokenType(String value) {
        Assert.hasText(value, "value cannot be empty");
        this.value = value;
    }

    /**
     * Returns the value of the token type.
     * @return the value of the token type
     */
    public String getValue() {
        return this.value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }
        OAuth2TokenType that = (OAuth2TokenType) obj;
        return getValue().equals(that.getValue());
    }

    @Override
    public int hashCode() {
        return getValue().hashCode();
    }


}
