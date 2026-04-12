package com.oauth.auth_server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.CookieManager;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AuthorizationEndpointE2ETest {

    @LocalServerPort
    private int port;

    private HttpClient httpClient;

    @BeforeEach
    void setUp() {
        httpClient = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

//    @Test
//    void authorize_requiresAuthentication() throws Exception {
//        System.out.println("[E2E] authorize_requiresAuthentication - start");
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create("http://localhost:" + port + "/oauth2/authorize"))
//                .GET()
//                .build();
//
//        HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
//        System.out.println("[E2E] authorize_requiresAuthentication - status=" + response.statusCode());
//        System.out.println("[E2E] authorize_requiresAuthentication - location="
//                + response.headers().firstValue("Location").orElse("(none)"));
//
//        assertThat(response.statusCode()).isEqualTo(HttpStatus.FOUND.value());
//        String location = response.headers().firstValue("Location").orElse("");
//        assertThat(location).contains("/login");
//        System.out.println("[E2E] authorize_requiresAuthentication - done");
//    }

    /**
     * 정상 흐름: 로그인 → 동의 화면 → 동의 승인 → 인가 코드 발급 (302 redirect)
     *
     * 1번 시나리오:
     *   1. POST /login → 302 (세션 쿠키 획득)
     *   2. GET  /oauth2/authorize → 200 동의 화면 (동의 이력 없음)
     *   3. POST /oauth2/authorize action=approve → 302 redirect_uri?code=xxx&state=yyy
     */
    @Test
    @DisplayName("1번 시나리오 정상 흐름: 동의 승인 후 인가 코드를 포함한 redirect를 받는다")
    void normalFlow_approveConsent_redirectsWithCode() throws Exception {
        login();

        String redirectUri = "http://localhost:8080/callback";
        String state = "state-123";
        String scope = "read";

        // Step 1: GET /oauth2/authorize → 동의 화면 (200)
        String authorizeUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

        HttpResponse<String> authorizeResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(authorizeUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.OK.value());
        System.out.println("[E2E] authorizeResponse.HttpStatus=\n" + authorizeResponse.statusCode());
        System.out.println("[E2E] authorizeResponse.body=\n" + authorizeResponse.body());
        assertThat(authorizeResponse.body()).contains("/oauth2/authorize");

        // Step 2: POST /oauth2/authorize action=approve → 302 + code
        String consentBody = "client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8)
                + "&action=approve";

        HttpResponse<Void> consentResponse = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:" + port + "/oauth2/authorize"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(consentBody))
                        .build(),
                HttpResponse.BodyHandlers.discarding());

        String location = consentResponse.headers().firstValue("Location").orElse("");
        System.out.println("[E2E] normalFlow_approveConsent - status=" + consentResponse.statusCode());
        System.out.println("[E2E] normalFlow_approveConsent - location=" + location);

        assertThat(consentResponse.statusCode()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(location).startsWith(redirectUri);
        assertThat(location).contains("code=");
        assertThat(location).contains("state=" + state);
    }

    @Test
    @DisplayName("2번 시나리오 흐름 : 동의 없이 GET 하면 동의 화면이 뜬다.")
    void noConsent_showsConsentPage() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=read"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("[E2E] 2번 시라니오 - status=" + authorizeResponse.statusCode());
        System.out.println("[E2E] 2번 시나리오 - body-length=" + authorizeResponse.body().length());

        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(authorizeResponse.body()).contains("test-client");  // clientId 렌더링
        assertThat(authorizeResponse.body()).contains("read");          // scope 렌더링
        assertThat(authorizeResponse.body()).contains("state-123");     // state hidden field
        assertThat(authorizeResponse.body()).contains("approve");       // 승인 버튼
    }


    @Test
    @DisplayName("3번 시나리오 흐름 : client_id 없이 요청 결과는 400이 나와야함.")
    void missingClientId_returns400() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=read"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }

    @Test
    @DisplayName("4번 시나리오 흐름 : 미등록 client_id -> 요청 결과는 400이 나와야함.")
    void unregisteredClientId_returns400() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=no-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=read"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }


    @Test
    @DisplayName("5번 시나리오 흐름 : 미등록 redirect_uri -> 요청 결과는 400이 나와야함.")
    void unregisteredRedirectUri_returns400() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/no";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=read"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    /**
     * 미등록 scope 시나리오
     * 1.validateResponseType()  → OK
     * 2. findClient() → OK (client_id 유효)
     * 3. resolveRedirectUri()    → OK → resolvedRedirectUri 확정
     * 4. validateScopes() → invalid_scope 예외 발생  단, 예외에 resolvedRedirectUri를 담아서 던짐
     * scope 검증 시점에서는 이미 redirect_uri가 검증되었기 때문에 에러를 redirect로 돌려보내는 것이 RFC 6749 스펙
     * @throws Exception
     */
    @Test
    @DisplayName("6번 시나리오 흐름 : 미등록 scope -> 요청 결과는 302이 나와야함.")
    void unregisteredScope_returns302() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" +
                URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=unknown-scope"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.FOUND.value());
        System.out.println("[E2E] status=" + authorizeResponse.statusCode());
        System.out.println("[E2E] location=" + authorizeResponse.headers().firstValue("Location").orElse("(none)"));
        System.out.println("[E2E] body=" + authorizeResponse.body());
        String location = authorizeResponse.headers().firstValue("Location").orElse("");
        assertThat(location).contains("invalid_scope");
    }

    @Test
    @DisplayName("7번 시나리오 흐름 : response_type=token-> 요청 결과는 unsupported, 302이 나와야함.")
    void unsupportedResponseType_redirectsWithError() throws Exception{
        System.out.println("[E2E] 로그인 진행 - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=token"
                + "&client_id=test-client"
                + "&redirect_uri=" +
                URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=unknown-scope"
                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();

        HttpResponse<String> authorizeResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.FOUND.value());
        System.out.println("[E2E] status=" + authorizeResponse.statusCode());
        System.out.println("[E2E] location=" + authorizeResponse.headers().firstValue("Location").orElse("(none)"));
        System.out.println("[E2E] body=" + authorizeResponse.body());
        String location = authorizeResponse.headers().firstValue("Location").orElse("");
        assertThat(location).contains("unsupported");
    }

    /**
     * 요청: GET /oauth2/authorize?...&scope=unknown&state=abc123
     * 에러 발생 (invalid_scope) -> 응답: 302 Location: http://localhost:8080/callback?error=invalid_scope&state=abc123
     *   ↑ state가 그대로 전달
     * @throws Exception
     */
    @Test
    @DisplayName("8번 시나리오 흐름 : state 포함 시 error redirect 에도 state 전달 ")
    void errorRedirect_includesState() throws Exception{
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=unknown-scope"
                + "&state=state-123";

        HttpResponse<String> authorizeResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        String location = authorizeResponse.headers().firstValue("Location").orElse("");
        System.out.println("[E2E] status=" + authorizeResponse.statusCode());
        System.out.println("[E2E] location=" + location);

        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(location).contains("error=");
        assertThat(location).contains("state=state-123");
    }


    /**
     * 다음 테스트는 사용자가 /oauth2/authorize에 접근했을 때 보안 필터를 통과하고, 동의 이력이 없으면 동의 화면가는지만 검증
     * 하는 테스트
     * @throws Exception
     */
    @Test
    void loggedInUser_canPassSecurityOnAuthorizeEndpoint() throws Exception {
        System.out.println("[E2E] loggedInUser_canPassSecurityOnAuthorizeEndpoint - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String requestUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=read";
//                + "&state=state-123";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestUri))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("[E2E] loggedInUser_canPassSecurityOnAuthorizeEndpoint - status=" + response.statusCode());
        System.out.println("[E2E] loggedInUser_canPassSecurityOnAuthorizeEndpoint - body-length=" + response.body().length());

        // 동의 이력이 없으므로 인가코드 발급 대신 동의 화면(200)이 반환된다.
        assertThat(response.statusCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.body()).contains("/oauth2/authorize");
        System.out.println("[E2E] loggedInUser_canPassSecurityOnAuthorizeEndpoint response.body : " + response.body());
        System.out.println("[E2E] loggedInUser_canPassSecurityOnAuthorizeEndpoint - done");

    }

    private void login() throws Exception {
        String loginUri = "http://localhost:" + port + "/login";
        String body = "username=user&password=1234";
        System.out.println("[E2E] login - request uri=" + loginUri);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(loginUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<Void> loginResponse = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        System.out.println("[E2E] login - status=" + loginResponse.statusCode());
        System.out.println("[E2E] login - location="
                + loginResponse.headers().firstValue("Location").orElse("(none)"));

        assertThat(loginResponse.statusCode()).isEqualTo(HttpStatus.FOUND.value());
        System.out.println("[E2E] login - done");
    }
}
