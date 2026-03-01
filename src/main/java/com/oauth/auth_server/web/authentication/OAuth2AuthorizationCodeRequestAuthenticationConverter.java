package com.oauth.auth_server.web.authentication;

import com.oauth.auth_server.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
            "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    private final RequestMatcher requestMatcher = createDefaultRequestMatcher();


    private static RequestMatcher createDefaultRequestMatcher(){
        RequestMatcher getMethodMatcher = (request) -> "GET".equals(request.getMethod());
        RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
        RequestMatcher responseTypeParameterMatcher = (
                request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
        return new OrRequestMatcher(getMethodMatcher,
                new AndRequestMatcher(postMethodMatcher, responseTypeParameterMatcher));
    }

    @Override
    public Authentication convert(HttpServletRequest request) {

        if (!this.requestMatcher.matches(request)){
            return null;
        }

        /**
         * 라미터 파싱 (GET이면 QueryString, POST면 Form Body)
         * 이건 RFC 6749 기본 범위에 포함되는 "요청 파싱" 로직
         */
        MultiValueMap<String, String> parameters = "GET".equals(request.getMethod())
                ? OAuth2EndpointUtils.getQueryParameters(request) : OAuth2EndpointUtils.getFormParameters(request);

        // response_type (REQUIRED) - Authorization Code Grant는 "code"만 지원
        /**
         * RFC 6749 기본: response_type 검사
         * RFC 6749 (4.1.1 Authorization Request) - Authorization Code Grant 전용 검증
         * - response_type: REQUIRED, 값은 "code" 이어야 함
         * - response_type 파라미터는 1개만 허용 (중복 파라미터 방지)
         */
        String responseType = parameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
        if (!StringUtils.hasText(responseType) || parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
        }
        else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
            throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
        }

        String authorizationUri = request.getRequestURL().toString();

        // client_id (REQUIRED)
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }


        // 현재 사용자(리소스 오너) Principal 확보 (로그인 전이면 anonymous)
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            principal = ANONYMOUS_AUTHENTICATION;
        }

        // redirect_uri (OPTIONAL)
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) && parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
        }

        // scope (OPTIONAL)
        Set<String> scopes = null;
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }
        if (StringUtils.hasText(scope)) {
            scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // state (RECOMMENDED)
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(state) && parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        // RFC 6749 기본 Authorization Code Request
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                authorizationUri,
                clientId,
                principal,
                redirectUri,
                state,
                scopes,
                Collections.emptyMap()
        );


    }

    private static void throwError(String errorCode, String parameterName) {
        throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
    }

    /**
     * OAuth 2.0 명세에 맞는 OAuth2Error 객체를 만들고,
     * 그것을 OAuth2AuthorizationCodeRequestAuthenticationException으로 감싸서 던진다.
     */

    private static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}
