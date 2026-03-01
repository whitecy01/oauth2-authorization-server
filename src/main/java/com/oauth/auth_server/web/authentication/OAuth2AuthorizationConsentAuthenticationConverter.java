package com.oauth.auth_server.web.authentication;


import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

public class OAuth2AuthorizationConsentAuthenticationConverter implements AuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
            "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    private final RequestMatcher requestMatcher = createDefaultRequestMatcher();

    @Override
    public Authentication convert(HttpServletRequest request) {
        /**
         * Authorization Endpoint 요청을 받는다 (/oauth2/authorize)
         */
        if (!this.requestMatcher.matches(request)) {
            return null;
        }

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

        String authorizationUri = request.getRequestURL().toString();

        /**
         * ClientId 검증
         */
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }

        /**
         * 동의 목록
         */
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            principal = ANONYMOUS_AUTHENTICATION;
        }

        /**
         * state 파라미터 처리
         * 동의 제출 구현에서는 보통 필수처럼 강제하는 경우가 많음
         */
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        if (!StringUtils.hasText(state) || parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        /**
         * scope 파라미터 처리
         */
        // scope (OPTIONAL)
        Set<String> scopes = null;
        if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
        }

        /**
         * client_id, state, scope를 제외한 모든 요청 파라미터를 additionalParameters에 담는다.
         */
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.CLIENT_ID) && !key.equals(OAuth2ParameterNames.STATE)
                    && !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            }
        });

        /**
         * 사용자가 특정 클라이언트에 대해 scope에 동의했다”는 사실을 표현하는 Authentication 객체다.
         */
        return new OAuth2AuthorizationConsentAuthenticationToken(authorizationUri, clientId, principal, state, scopes,
                additionalParameters);
    }

    /**
     * POST 이면서 response_type 파라미터가 없는 요청만 매칭하는 RequestMatcher
     */
    private static RequestMatcher createDefaultRequestMatcher() {
        RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
        RequestMatcher responseTypeParameterMatcher = (
                request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
        return new AndRequestMatcher(postMethodMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));
    }


    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}
