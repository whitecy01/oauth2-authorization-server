package com.oauth.auth_server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Slf4j
public class TokenEndPointE2ETest {
    private static final String AUTHORIZATION_CODE = "test-authorization-code";
    private static final String CLIENT_ID = "test-client";
    private static final String USERNAME = "user";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    private static final String STATE = "state-123";

    @LocalServerPort
    private int port;

    @Autowired
    private OauthAuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private OauthAccessTokenRepository accessTokenRepository;

    private HttpClient httpClient;

    @BeforeEach
    void setUp(){
        accessTokenRepository.deleteAll();
        authorizationCodeRepository.deleteAll();
        authorizationCodeRepository.save(new OauthAuthorizationCode(
                AUTHORIZATION_CODE,
                CLIENT_ID,
                USERNAME,
                REDIRECT_URI,
                STATE,
                Instant.now(),
                Instant.now().plusSeconds(300)
        ));

        httpClient = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Test
    void User_giveAuthorizationCodeNextAccessToken() throws IOException, InterruptedException {
        log.info("[E2E] User_giveAuthorizationCodeNextAccessToken - start");
        OauthAuthorizationCode authorizationCode = authorizationCodeRepository.findByCode(AUTHORIZATION_CODE)
                .orElseThrow(() -> new IllegalStateException("authorization code not found"));

        String code = authorizationCode.getCode();
        String clientId = authorizationCode.getClientId();
        String username = authorizationCode.getUsername();
        String redirectUri = authorizationCode.getRedirectUri();
        String state = authorizationCode.getState();

        log.info("code={}, clientId={}, username={}, redirectUri={}, state={}",
                code, clientId, username, redirectUri, state);

        String credentials = CLIENT_ID + ":" + "secret";
        String basicAuth = Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        String requestBody = "grant_type=authorization_code"
                + "&code=" + code
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/oauth2/token"))
                .header("Authorization", "Basic " + basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        log.info("[E2E] response - status=" + response.statusCode());
        log.info("[E2E] response - body=" + response.body());
        assertThat(response.statusCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.body()).contains("access_token");
    }

    @Test
    void User_giveAccessTokenNextUserInfo() throws IOException, InterruptedException {
        log.info("[E2E] User_giveAccessTokenNextUserInfo - start");
        OauthAuthorizationCode authorizationCode = authorizationCodeRepository.findByCode(AUTHORIZATION_CODE)
                .orElseThrow(() -> new IllegalStateException("authorization code not found"));
        log.info("[E2E] authorization code loaded - code={}, redirectUri={}",
                authorizationCode.getCode(), authorizationCode.getRedirectUri());

        String basicAuth = Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + "secret").getBytes(StandardCharsets.UTF_8));
        log.info("[E2E] basic auth prepared for clientId={}", CLIENT_ID);

        String tokenRequestBody = "grant_type=authorization_code"
                + "&code=" + authorizationCode.getCode()
                + "&redirect_uri=" + URLEncoder.encode(authorizationCode.getRedirectUri(), StandardCharsets.UTF_8);
        log.info("[E2E] token request body={}", tokenRequestBody);

        HttpRequest tokenRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/oauth2/token"))
                .header("Authorization", "Basic " + basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(tokenRequestBody))
                .build();
        log.info("[E2E] token request uri={}", tokenRequest.uri());

        HttpResponse<String> tokenResponse = httpClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
        log.info("[E2E] token response status={}", tokenResponse.statusCode());
        log.info("[E2E] token response body={}", tokenResponse.body());
        assertThat(tokenResponse.statusCode()).isEqualTo(HttpStatus.OK.value());

        String responseBody = tokenResponse.body();
        String accessToken = responseBody.substring(
                responseBody.indexOf("\"access_token\":\"") + 16,
                responseBody.indexOf("\",\"token_type\"")
        );
        log.info("[E2E] access token extracted={}", accessToken);

        HttpRequest resourceRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/resource/me"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        log.info("[E2E] resource request uri={}", resourceRequest.uri());

        HttpResponse<String> resourceResponse = httpClient.send(resourceRequest, HttpResponse.BodyHandlers.ofString());
        log.info("[E2E] resource response status={}", resourceResponse.statusCode());
        log.info("[E2E] resource response body={}", resourceResponse.body());

        assertThat(resourceResponse.statusCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(resourceResponse.body()).contains("\"username\":\"user\"");
        assertThat(resourceResponse.body()).contains("\"email\":\"user@example.com\"");
        log.info("[E2E] User_giveAccessTokenNextUserInfo - done");
    }
}
