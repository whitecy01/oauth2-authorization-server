package com.oauth.auth_server.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

public class OAuth2EndpointUtils {
    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private OAuth2EndpointUtils() {
    }

    /**
     * HTTP 요청에서 “폼(body) 파라미터만” 추출하는 유틸리티 함수
     * 인가 요청에서는 GET, POST 방식 두개가 올 수 있다. 문제는 query + form 둘 다 합쳐서 반환한다는 점
     * 이 함수는 request.getParameterMap()을 호출해서 query + from 모두 가져오고 queryString에 포함된 key는 제외하고 남은 것만 form 파라미터로 간주
     * GET은 빈 Map, POST form 요청 -> body 파라미터만 포함, scope 다중 값 List로 들어감
     * POST 예시
     * POST /oauth2/authorize?client_id=abc
     * Content-Type: application/x-www-form-urlencoded
     *
     * response_type=code&scope=read&state=xyz
     * {
     *   client_id -> ["abc"],   // query
     *   response_type -> ["code"], // form
     *   scope -> ["read"],         // form
     *   state -> ["xyz"]           // form
     * }
     */
    static MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            // If not query parameter then it's a form parameter
            if (!queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    /**
     * 이건 Query 부분만 가져오기
     */
    static MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }



}
