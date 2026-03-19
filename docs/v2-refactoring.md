# V2 리팩터링 계획

## 배경과 목표

지금까지 진행한 것은 내가 인가 서버를 직접 만들어보고 E2E Test 및 유닛 테스트를 통해 검증까지 진행해보았다. 그러면 내가 만든 코드를 통해 이제 Spring Authorization Server 프레임워크 코드로 점점 바꾸어보려고 한다.

현재 내가 만든 코드는 다음과 같다.

- `AuthorizationController`와 `TokenController`에 파라미터 파싱, RFC 검증, 클라이언트 조회, 비즈니스 로직, 토큰 발급, 에러 처리가 모두 포함되어 있다.

우선

- Spring Authorization Server의 설계 패턴(불변 요청 컨텍스트 → Provider → 서비스 추상화)을 참고해 책임을 명확히 분리한다. 엔드포인트 단위로 작업을 나눠 각 구간이 끝날 때 E2E 테스트로 검증한다.

### 방향

Spring Authorization Server(SAS)의 설계 패턴을 참고해 책임을 아래 세 레이어로 분리한다.

```
Controller (HTTP 어댑터)
    ↓  불변 요청 컨텍스트 객체 전달
Provider (비즈니스 로직 + 검증 조율)
    ↓  Validator / Service 호출
Validator / Service (단일 책임 컴포넌트)
```

- **Controller**는 HTTP 파라미터를 읽어 요청 컨텍스트 객체를 만들고, Provider를 호출하고, 결과를 HTTP 응답으로 변환하는 역할만 한다.
- **Provider**는 Validator를 순서대로 호출하고 code/token 발급을 지휘한다. HTTP를 모른다.
- **Validator**는 하나의 검증 규칙만 담당한다. MockMvc 없이 순수 Java로 단위 테스트할 수 있다.

엔드포인트 단위(인가 → 토큰)로 작업을 나눠 각 구간이 끝날 때 기존 E2E 테스트로 회귀를 확인한다.

---

## 인가 엔드포인트 리팩터링 (`/oauth2/authorize`)

### 현재 구조의 문제

`AuthorizationController.authorize()`가 아래 7가지를 순서대로 처리한다.

1. `response_type` 검증
2. `client_id` 검증 + DB 조회
3. `redirect_uri` 형식 검증 + DB 등록값 비교
4. `scope` 중복 파라미터 검사
5. `scope` 형식 검사 + 클라이언트 허용 scope 비교
6. 동의 여부 확인 → 동의 화면 or code 발급 분기
7. code 발급 + DB 저장

이 중 어느 하나의 검증 규칙이 바뀌어도 메서드 전체를 읽어야 하고, 특정 검증 로직만 단독으로 테스트할 수 없다.

### 작업 순서 개요

기존 테스트를 깨뜨리지 않으면서 점진적으로 교체한다.

- **1-1 ~ 1-2**: 새로운 레이어에서 공통으로 쓸 타입(에러, 도메인 객체, 서비스 인터페이스)을 먼저 만든다. 기존 코드는 전혀 건드리지 않는다.
- **1-3 ~ 1-5**: Controller와 분리된 Validator, Provider를 만든다. 이 단계에서도 기존 Controller는 그대로다.
- **1-6**: Controller를 HTTP 어댑터로 교체하고, 기존 `@WebMvcTest` 테스트를 Provider mock 기반으로 전환한다.

---

### 작업 1-1: Core 에러 타입 도입

**왜 하는가**

현재 컨트롤러는 `"invalid_request"`, `"invalid_scope"` 같은 에러 코드를 문자열 리터럴로 직접 작성한다. Validator와 Provider가 에러를 던질 수 있으려면, 공통으로 쓸 에러 타입과 예외 클래스가 먼저 필요하다.

**무엇을 만드는가**

- `oauth2/core/OAuth2Error.java` — `record OAuth2Error(String errorCode, String description)`. 에러 코드와 설명을 하나의 값 객체로 묶는다. Spring Security의 `org.springframework.security.oauth2.core.OAuth2Error`를 참고하되 직접 구현한다.
- `oauth2/core/OAuth2AuthorizationException.java` — `OAuth2Error`를 보유하는 `RuntimeException`. Validator와 Provider가 이 예외를 던지면 Controller가 잡아서 HTTP 응답(302 redirect error or 400)으로 변환한다.

기존 코드 변경 없음 / 테스트 영향 없음

---

### 작업 1-2: 도메인 객체 + 저장소 추상화 도입

**왜 하는가**

현재 Controller는 클라이언트 정보를 얻기 위해 JPA 레포지토리 3개(`OauthClientRepository`, `OauthClientRedirectUriRepository`, `OauthClientScopeRepository`)를 직접 주입받는다. Validator와 Provider는 "클라이언트가 등록되어 있는지", "허용된 redirect_uri인지" 같은 비즈니스 질문에만 관심이 있고, 데이터가 JPA로 어떻게 저장되어 있는지는 알 필요가 없다.

두 가지를 새로 만든다.

1. **`RegisteredClient` 도메인 객체**: JPA 엔티티 `OauthClient`를 Validator/Provider 레이어에 노출하지 않기 위한 값 객체다. `OauthClient`, `OauthClientRedirectUri`, `OauthClientScope` 세 엔티티의 데이터를 하나로 합쳐 표현한다. SAS의 `RegisteredClient`와 같은 역할이다.
2. **`RegisteredClientRepository` 인터페이스**: `findByClientId()`가 `RegisteredClient`를 반환한다. Validator는 이 인터페이스만 알면 되고, JPA 구현 세부사항은 모른다.

또한 인가 코드·액세스 토큰의 생명주기(저장, 조회, 삭제)를 담당하는 `OAuth2AuthorizationService` 인터페이스도 함께 만든다. 현재 Controller가 `OauthAuthorizationCodeRepository`를 직접 다루는 것을 추상화 뒤로 숨기는 것이다.

**무엇을 만드는가**

- `oauth2/core/RegisteredClient.java` (도메인 값 객체)
  - `String clientId`, `String clientSecret`, `List<String> redirectUris`, `List<String> scopes`, `boolean active`

- `oauth2/service/RegisteredClientRepository.java` (인터페이스)
  - `Optional<RegisteredClient> findByClientId(String clientId)`

- `oauth2/service/JpaRegisteredClientRepository.java` (구현체)
  - JPA 레포 3개에 위임해 `OauthClient` → `RegisteredClient` 변환. 로직 없이 순수 어댑터.

- `oauth2/service/OAuth2AuthorizationService.java` (인터페이스)
  - `void saveAuthorizationCode(String code, String clientId, String username, String redirectUri, String state, Instant expiresAt)`
  - `Optional<OauthAuthorizationCode> findByCode(String code)`
  - `void deleteByCode(String code)`
  - 인가 엔드포인트에 필요한 메서드만 우선 정의. 토큰 관련은 작업 2-1에서 추가한다.

- `oauth2/service/JpaOAuth2AuthorizationService.java` (구현체)
  - `OauthAuthorizationCodeRepository`에 위임

기존 코드 변경 없음 / 테스트 영향 없음

---

### 작업 1-3: 요청 컨텍스트 객체 도입

**왜 하는가**

현재 Controller의 검증 로직은 `@RequestParam` 값들을 그대로 참조한다. Provider와 Validator에 HTTP 파라미터를 넘기려면, HTTP와 분리된 불변 객체가 필요하다. 이 객체가 있어야 Validator를 MockMvc 없이 단위 테스트할 수 있다.

**무엇을 만드는가**

- `oauth2/authorization/AuthorizationCodeRequestToken.java`
  - HTTP 파라미터를 파싱해 정리한 불변 값 객체. Controller가 이 객체를 만들어 Provider에 넘긴다.
  - `String responseType`, `String clientId`, `String redirectUri`(nullable), `List<String> scopes`, `String state`(nullable), `String username`, `int rawScopeParamCount`(scope 파라미터 중복 검사용)
  - SAS 참고: `OAuth2AuthorizationCodeRequestAuthenticationToken`

기존 코드 변경 없음 / 테스트 영향 없음

---

### 작업 1-4: Validator 4개 생성

**왜 하는가**

현재 Controller의 검증 로직은 하나의 메서드에 섞여 있어서, 예를 들어 `redirect_uri` 검증만 단독으로 테스트하는 게 불가능하다. 각 검증 규칙을 독립 클래스로 분리하면 MockMvc 없이 순수 Java 단위 테스트로 경계값을 검증할 수 있다.

`AuthorizationCodeRequestValidator` 인터페이스를 정의하고, 4개의 구현체로 Controller의 검증 로직을 이동시킨다.

```java
void validate(AuthorizationCodeRequestToken token) throws OAuth2AuthorizationException;
```

**무엇을 만드는가**

- `oauth2/authorization/validator/ResponseTypeValidator.java`
  - `response_type`이 없거나 빈 값이면 `invalid_request`, `"code"`가 아니면 `unsupported_response_type`을 던진다.
  - 현재 Controller L54-64 로직을 이동

- `oauth2/authorization/validator/AuthorizationClientValidator.java`
  - `client_id`가 없으면 `invalid_request`, 존재하지 않거나 비활성 클라이언트면 `invalid_client`를 던진다.
  - `RegisteredClientRepository`로 `RegisteredClient`를 조회해 검증한다.
  - 현재 Controller L66-79 로직을 이동

- `oauth2/authorization/validator/RedirectUriValidator.java`
  - `redirect_uri`가 비어 있거나, `#`을 포함하거나, 등록 목록에 없으면 `invalid_request`를 던진다.
  - URI를 제공하지 않았는데 등록된 URI가 2개 이상이어도 `invalid_request`를 던진다.
  - `RegisteredClient.redirectUris()`로 검증한다.
  - 현재 Controller L71-95 로직을 이동

- `oauth2/authorization/validator/ScopeValidator.java`
  - `scope` 파라미터가 중복으로 넘어오거나, RFC §3.3 패턴에 맞지 않거나, 클라이언트 허용 범위를 벗어나면 `invalid_scope`를 던진다.
  - `SCOPE_TOKEN_PATTERN`을 이 클래스로 이동한다.
  - `RegisteredClient.scopes()`로 검증한다.
  - 현재 Controller L97-126 로직을 이동

**테스트**: 각 Validator별 단위 테스트 파일 4개. MockMvc 불필요, mock `RegisteredClientRepository`로 경계값 케이스 검증.

기존 테스트 영향 없음 (Validator는 아직 Controller에 연결되지 않음)

---

### 작업 1-5: AuthorizationCodeRequestProvider 생성

**왜 하는가**

Validator들을 만들었지만, 이것들을 어떤 순서로 호출하고 code를 어떻게 발급할지를 조율하는 컴포넌트가 없다. Provider가 그 역할을 한다. Controller는 Provider에 요청 컨텍스트만 넘기고, "동의 필요", "코드 발급 성공", "검증 실패" 중 어떤 결과인지만 받으면 된다.

**무엇을 만드는가**

- `oauth2/authorization/AuthorizationCodeIssuedToken.java`
  - Provider가 code 발급에 성공했을 때 반환하는 결과 객체. `String code`, `String redirectUri`, `String state`를 담는다.

- `oauth2/authorization/ConsentRequiredException.java`
  - 사용자가 아직 동의하지 않은 경우 Provider가 던지는 예외. Controller가 이를 잡아서 동의 화면에 필요한 데이터(`RegisteredClient`, `username`, `requestedScopes`, 원본 파라미터들)를 model에 담아 뷰를 렌더링한다.

- `oauth2/authorization/AuthorizationCodeRequestProvider.java`
  - Validator 4개, `AuthorizationConsentService`, `OAuth2AuthorizationService`, `RegisteredClientRepository`를 주입받는다.
  - `process(token)`: 검증 → 동의 확인 → code 발급 또는 예외를 순서대로 수행한다.
  - SAS 참고: `OAuth2AuthorizationCodeRequestAuthenticationProvider`

**테스트**: Provider 단위 테스트. 각 Validator mock + ConsentService mock 조합으로 흐름 검증.

기존 테스트 영향 없음

---

### 작업 1-6: AuthorizationController를 HTTP 어댑터로 교체

**왜 하는가**

1-1 ~ 1-5에서 만든 컴포넌트들을 실제로 연결하는 단계다. Controller에서 비즈니스 로직을 모두 걷어내고, HTTP ↔ 도메인 변환만 남긴다. 기존 `@WebMvcTest` 테스트들은 Controller가 직접 검증 로직을 들고 있다는 가정으로 작성되어 있어서 함께 업데이트한다.

**Controller 변경 내용**

`GET /oauth2/authorize`:
- HTTP 파라미터 → `AuthorizationCodeRequestToken` 생성 → `provider.process()` 호출
- `AuthorizationCodeIssuedToken` 반환 시 → 302 redirect (`?code=...&state=...`)
- `ConsentRequiredException` 발생 시 → model에 데이터 설정 → `"oauth2/consent"` 뷰 렌더링
- `OAuth2AuthorizationException` 발생 시 → 302 error redirect 또는 400 응답

`POST /oauth2/authorize`:
- `"deny"` 제출 시 → error redirect
- `"approve"` 제출 시 → `consentService.saveConsent()` → `provider.issueCode()` → 302 redirect

**제거되는 것들**
- 직접 주입하던 JPA 레포지토리 4개(`OauthClientRepository` 등) 제거
- 컨트롤러 내부 private 메서드(`SCOPE_TOKEN_PATTERN`, `splitScopes()`, `issueAuthorizationCode()`, `buildErrorRedirectUri()`) 제거

**테스트 업데이트**: `@WebMvcTest` 테스트 5개에서 기존 JPA 레포 mock을 제거하고 `AuthorizationCodeRequestProvider` mock으로 교체.

**검증**: `./gradlew test` 전체 통과 + `AuthorizationEndpointE2ETest` 통과 확인

---

### 인가 엔드포인트 일정

| 일차 | 작업 | 산출물 |
|------|------|--------|
| Day 1 | 작업 1-1, 1-2 | OAuth2Error, OAuth2AuthorizationException, RegisteredClient, RegisteredClientRepository, OAuth2AuthorizationService |
| Day 2 | 작업 1-3, 1-4 (Validator 2개) | AuthorizationCodeRequestToken, ResponseTypeValidator, AuthorizationClientValidator + 단위 테스트 |
| Day 3 | 작업 1-4 나머지 (Validator 2개) | RedirectUriValidator, ScopeValidator + 단위 테스트 |
| Day 4 | 작업 1-5 | AuthorizationCodeIssuedToken, ConsentRequiredException, AuthorizationCodeRequestProvider + 단위 테스트 |
| Day 5 | 작업 1-6 | AuthorizationController 교체, 기존 테스트 5개 업데이트, E2E 테스트 통과 확인 |

---

## 토큰 엔드포인트 리팩터링 (`/oauth2/token`)

### 현재 구조의 문제

`TokenController.issueAccessToken()`이 아래 7가지를 한 메서드에서 처리한다.

1. `grant_type` 검증 (null, 중복, 값 검사)
2. `code` 검증 (null, 중복)
3. `redirect_uri` 검증 (null, 중복)
4. 클라이언트 인증 (Basic 헤더 or form 파라미터 파싱)
5. 클라이언트 조회 + secret 비교
6. authorization code 존재/만료/client 바인딩/redirect_uri 일치 검증
7. access token 발급 + DB 저장, code 삭제

인가 엔드포인트와 같은 이유로 테스트 단위가 크고 책임이 뒤섞여 있다. 인가 엔드포인트와 동일한 패턴(Provider + 요청 컨텍스트)을 적용해 교체한다.

---

### 작업 2-1: Core 값 객체 추가 + 서비스 추상화 보완

**왜 하는가**

토큰 엔드포인트에서 쓸 타입이 추가로 필요하다. `"authorization_code"` 문자열 비교를 enum으로 바꾸고, Provider가 반환할 access token 결과 객체를 만든다. 또한 작업 1-2에서 만든 `OAuth2AuthorizationService`에 access token 저장 메서드를 추가한다.

**무엇을 만드는가**

- `oauth2/core/AuthorizationGrantType.java` — `enum { AUTHORIZATION_CODE }`. `"authorization_code".equals(...)` 문자열 비교를 타입으로 통일한다.
- `oauth2/core/OAuth2AccessToken.java` — `String tokenValue`, `Instant issuedAt`, `Instant expiresAt`. Provider가 반환하는 결과 값 객체. JPA 엔티티 `OauthAccessToken`과는 별개다.
- `OAuth2AuthorizationService`에 `void saveAccessToken(...)` 추가. `JpaOAuth2AuthorizationService`에서 `OauthAccessTokenRepository`에 위임하도록 구현한다.

기존 테스트 영향 없음

---

### 작업 2-2: 요청 컨텍스트 객체 + ClientCredentialsExtractor 생성

**왜 하는가**

인가 엔드포인트와 마찬가지로, 토큰 엔드포인트의 HTTP 파라미터를 도메인 레이어에 그대로 넘기지 않기 위해 요청 컨텍스트 객체가 필요하다. 또한 현재 Controller의 `resolveClientCredentials()` private 메서드는 Basic 헤더 파싱이라는 독립적인 책임을 가지고 있어서, 별도 컴포넌트로 분리하면 단독으로 테스트할 수 있다.

**무엇을 만드는가**

- `oauth2/token/AuthorizationCodeTokenRequest.java` — 토큰 요청 파라미터를 담는 불변 객체. `grantType`, `code`, `redirectUri`, `clientId`, `clientSecret`(nullable), `authorizationHeader`, 중복 파라미터 카운트 3개를 담는다.
- `oauth2/token/ClientCredentials.java` — `record ClientCredentials(String clientId, String clientSecret)`. 현재 TokenController의 private record를 독립 파일로 분리한다.
- `oauth2/token/ClientCredentialsExtractor.java` — Basic 헤더가 있으면 헤더에서, 없으면 form 파라미터에서 클라이언트 자격증명을 추출한다. SAS의 `ClientSecretBasicAuthenticationConverter`와 같은 역할이다.

**테스트**: `ClientCredentialsExtractorTest` — Basic 헤더 / form 파라미터 / 둘 다 없음 케이스.

기존 테스트 영향 없음

---

### 작업 2-3: AuthorizationCodeTokenProvider 생성

**왜 하는가**

인가 엔드포인트의 `AuthorizationCodeRequestProvider`와 같은 이유다. 현재 TokenController의 검증+발급 로직 전체를 Provider로 옮기면, Controller는 HTTP 어댑터 역할만 하게 되고, 검증 흐름은 MockMvc 없이 단위 테스트할 수 있다.

**무엇을 만드는가**

- `oauth2/token/AuthorizationCodeTokenProvider.java`
  - `RegisteredClientRepository`, `OAuth2AuthorizationService`, `ClientCredentialsExtractor`를 주입받는다.
  - `process(request)`: 아래 순서로 검증 후 access token을 발급한다.
    1. `grant_type` 검증 → `invalid_request` / `unsupported_grant_type`
    2. `code` 검증 → `invalid_request`
    3. `redirect_uri` 검증 → `invalid_grant` / `invalid_request`
    4. 클라이언트 자격증명 추출 실패 → `invalid_client`
    5. 클라이언트 조회 + secret 비교 → `invalid_client`
    6. 등록된 `redirect_uri` 비교 → `invalid_grant`
    7. code 조회 실패 → `invalid_grant`
    8. code 만료 → `deleteByCode()` 후 `invalid_grant`
    9. code의 `clientId` 불일치 → `invalid_grant`
    10. code의 `redirectUri` 불일치 → `invalid_grant`
    11. access token 발급 → `saveAccessToken()` → `deleteByCode()` → `OAuth2AccessToken` 반환
  - SAS 참고: `OAuth2AuthorizationCodeAuthenticationProvider`

**테스트**: 실패 케이스(7가지 이상) + 성공 케이스.

기존 테스트 영향 없음

---

### 작업 2-4: TokenController를 HTTP 어댑터로 교체

**왜 하는가**

인가 엔드포인트 작업 1-6과 같은 이유다. 2-1 ~ 2-3에서 만든 컴포넌트들을 실제로 연결하고, Controller에서 비즈니스 로직을 모두 걷어낸다.

**Controller 변경 내용**

`POST /oauth2/token`:
- HTTP 파라미터 → `AuthorizationCodeTokenRequest` 생성 → `provider.process()` 호출
- `OAuth2AccessToken` 반환 시 → JSON 응답 `{ access_token, token_type, expires_in }`
- `OAuth2AuthorizationException` 발생 시 → `invalid_client`면 401 + `WWW-Authenticate` 헤더, 그 외 400

**제거되는 것들**
- 직접 주입하던 JPA 레포지토리 4개 제거
- `resolveClientCredentials()`, private record `ClientCredentials`, `error()`, `invalidClient()`, `errorBody()` 제거
- `ACCESS_TOKEN_TTL_SECONDS` → Provider로 이동

**테스트 업데이트**: `@WebMvcTest` 테스트 4개에서 `AuthorizationCodeTokenProvider` mock으로 교체.

**검증**: `./gradlew test` 전체 통과 + `TokenEndPointE2ETest` 통과 확인

---

### 작업 2-5: Dead Code 제거

`SimpleClient.java`는 어디서도 참조되지 않는 파일이다. 삭제하고 `./gradlew test`로 최종 확인한다.

---

### 토큰 엔드포인트 일정

| 일차 | 작업 | 산출물 |
|------|------|--------|
| Day 6 | 작업 2-1 | AuthorizationGrantType, OAuth2AccessToken, OAuth2AuthorizationService 보완 |
| Day 7 | 작업 2-2 | AuthorizationCodeTokenRequest, ClientCredentials, ClientCredentialsExtractor + 단위 테스트 |
| Day 8 | 작업 2-3 | AuthorizationCodeTokenProvider + 단위 테스트 |
| Day 9 | 작업 2-4 | TokenController 교체, 기존 테스트 4개 업데이트, E2E 테스트 통과 확인 |
| Day 10 | 작업 2-5 | SimpleClient 삭제, 전체 `./gradlew test` 최종 확인 |

---

## 전체 산출물 요약

```
oauth2/
├── core/
│   ├── OAuth2Error.java                            (작업 1-1)
│   ├── OAuth2AuthorizationException.java           (작업 1-1)
│   ├── RegisteredClient.java                       (작업 1-2)
│   ├── AuthorizationGrantType.java                 (작업 2-1)
│   └── OAuth2AccessToken.java                      (작업 2-1)
├── authorization/
│   ├── AuthorizationCodeRequestToken.java          (작업 1-3)
│   ├── AuthorizationCodeIssuedToken.java           (작업 1-5)
│   ├── ConsentRequiredException.java               (작업 1-5)
│   ├── AuthorizationCodeRequestValidator.java      (작업 1-4)
│   ├── validator/
│   │   ├── ResponseTypeValidator.java              (작업 1-4)
│   │   ├── AuthorizationClientValidator.java       (작업 1-4)
│   │   ├── RedirectUriValidator.java               (작업 1-4)
│   │   └── ScopeValidator.java                     (작업 1-4)
│   └── AuthorizationCodeRequestProvider.java       (작업 1-5)
├── token/
│   ├── AuthorizationCodeTokenRequest.java          (작업 2-2)
│   ├── ClientCredentials.java                      (작업 2-2)
│   ├── ClientCredentialsExtractor.java             (작업 2-2)
│   └── AuthorizationCodeTokenProvider.java         (작업 2-3)
└── service/
    ├── RegisteredClientRepository.java             (작업 1-2)
    ├── JpaRegisteredClientRepository.java          (작업 1-2)
    ├── OAuth2AuthorizationService.java             (작업 1-2 + 2-1)
    └── JpaOAuth2AuthorizationService.java          (작업 1-2 + 2-1)
```

**수정 파일**
- `controller/AuthorizationController.java` (작업 1-6)
- `controller/TokenController.java` (작업 2-4)

**삭제 파일**
- `oauth/SimpleClient.java` (작업 2-5)

---

## 검증 기준

| 구간 | 검증 방법 |
|------|-----------|
| 작업 1-1 ~ 1-5 완료 시 | `./gradlew test` — 기존 테스트 전부 통과 |
| 작업 1-6 완료 시 | `./gradlew test` + `AuthorizationEndpointE2ETest` 통과 |
| 작업 2-1 ~ 2-3 완료 시 | `./gradlew test` — 기존 테스트 전부 통과 |
| 작업 2-4 완료 시 | `./gradlew test` + `TokenEndPointE2ETest` 통과 |
| 작업 2-5 완료 시 | `./gradlew test` 전체 최종 통과 |