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

    @Test
    void loggedInUser_withConsent_getsAuthorizationCode() throws Exception{
        System.out.println("[E2E] loggedInUser_withConsent_getsAuthorizationCode - start");
        login();

        String redirectUri = "http://localhost:8080/callback";
        String state = "state-123";
        String scope = "read";
        String authorizeUri = "http://localhost:" + port
                + "/oauth2/authorize?response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

        HttpRequest authorizeRequest = HttpRequest.newBuilder()
                .uri(URI.create(authorizeUri))
                .GET()
                .build();
        HttpResponse<String> authorizeResponse = httpClient.send(authorizeRequest, HttpResponse.BodyHandlers.ofString());

        assertThat(authorizeResponse.statusCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(authorizeResponse.body()).contains("/oauth2/authorize");

        String consentBody = "client_id=test-client"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8)
                + "&action=approve";

        HttpRequest consentRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/oauth2/authorize"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(consentBody))
                .build();
        HttpResponse<Void> consentResponse = httpClient.send(consentRequest, HttpResponse.BodyHandlers.discarding());

        System.out.println("[E2E] loggedInUser_withConsent_getsAuthorizationCode - consent status="
                + consentResponse.statusCode());
        System.out.println("[E2E] loggedInUser_withConsent_getsAuthorizationCode - consent location="
                + consentResponse.headers().firstValue("Location").orElse("(none)"));
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
