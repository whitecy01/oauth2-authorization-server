# OAuth2 Authorization Server 구현 계획 (RFC 6749 기반)

## 전체 전략

- **v2 완료** (현재): Controller → Provider 구조로 책임 분리
- **v3**: Filter → Converter → Provider 구조로 전환 (SAS 실제 패턴)

---

## ✅ 완료 — 인가 엔드포인트 v2

작업 1-1 ~ 1-5 완료. Controller를 HTTP 어댑터로 교체하고 Provider로 비즈니스 로직 분리.

---

# 1주차 — 토큰 엔드포인트 v2

## 3월 30일 (월) — 작업 2-1: Core 값 객체 추가

- `AuthorizationGrantType` enum
- `OAuth2AccessToken` 값 객체
- `OAuth2AuthorizationService`에 `saveAccessToken()` 추가
- `JpaOAuth2AuthorizationService` 구현

---

## 3월 31일 (화) — 작업 2-2: 요청 컨텍스트 객체 + Extractor

- `AuthorizationCodeTokenRequest` (불변 요청 객체)
- `ClientCredentials` record (별도 파일로 분리)
- `ClientCredentialsExtractor` (Basic 헤더 / form 파라미터 추출)
- `ClientCredentialsExtractorTest` 단위 테스트

---

## 4월 1일 (수) — 작업 2-3: AuthorizationCodeTokenProvider (1차)

- `grant_type` 검증 → `invalid_request` / `unsupported_grant_type`
- `code` 검증 → `invalid_request`
- `redirect_uri` 검증 → `invalid_grant` / `invalid_request`
- 클라이언트 자격증명 추출 실패 → `invalid_client`
- 클라이언트 조회 + secret 비교 → `invalid_client`

---

## 4월 2일 (목) — 작업 2-3: AuthorizationCodeTokenProvider (2차) + 단위 테스트

- 등록된 `redirect_uri` 비교 → `invalid_grant`
- code 조회 실패 / 만료 / clientId 불일치 / redirectUri 불일치 → `invalid_grant`
- access token 발급 → `saveAccessToken()` → `deleteByCode()` → `OAuth2AccessToken` 반환
- 단위 테스트 (실패 케이스 7가지 이상 + 성공 케이스)

---

## 4월 3일 (금) — 작업 2-4: TokenController → HTTP 어댑터 교체

- HTTP 파라미터 → `AuthorizationCodeTokenRequest` → `provider.process()` 호출
- `OAuth2AccessToken` 반환 시 → JSON 응답
- `OAuth2AuthorizationException` → `invalid_client`이면 401, 그 외 400
- JPA 레포지토리 직접 의존 제거
- `@WebMvcTest` 테스트 4개 → Provider mock 기반으로 교체
- `./gradlew test` + `TokenEndPointE2ETest` 통과 확인

---

## 4월 4일 (토) — 작업 2-5: Dead Code 제거 + 전체 검증

- `SimpleClient.java` 삭제
- `./gradlew test` 전체 최종 통과 확인

---


# 2주차 — 인가 엔드포인트 v3 (Filter 기반)

## 4월 5일 (월) — 설계

- Filter → Converter → Provider 흐름 설계
- SAS `OAuth2AuthorizationEndpointFilter` 구조 분석
- 브랜치 전략 확정 (`v3/filter-based`)

---

## 4월 6일 (화) — OAuth2AuthorizationEndpointFilter 구현

- `/oauth2/authorize` 요청을 Filter에서 가로채기
- Converter 호출 → `AuthenticationToken` 생성 → Provider 위임
- Controller 역할 축소 준비

---

## 4월 7일 (수) — Converter 구현

- HTTP 파라미터 → `OAuth2AuthorizationCodeRequestAuthenticationToken` 변환
- 중복 파라미터 카운트 처리
- Filter → Converter → Token 연결

---

## 4월 8일 (목) — Provider 연결

- Filter에서 Provider로 위임
- `AuthorizationCodeIssuedToken` / `ConsentRequiredException` 처리
- Filter에서 HTTP 응답 작성 (redirect, 동의 화면, 에러)

---

## 4월 9일 (금) — 흐름 마무리 + E2E 테스트

- 성공 흐름 (code 발급 → redirect)
- 동의 흐름 (consent 화면 렌더링)
- 실패 흐름 (redirect 가능 / 불가 에러)
- `AuthorizationEndpointE2ETest` 통과 확인

---

## 4월 10일 (토) — 테스트 정리

- authorize E2E 시나리오 표 작성 (정상 / 실패 / redirect 여부 / error 코드)
- 단위 테스트 보강

---

# 3주차 — 토큰 엔드포인트 v3 (Filter 기반) + 오류/lifecycle 강화

## 4월 11일 (월) — 토큰 엔드포인트 Filter 설계

- `OAuth2TokenEndpointFilter` 구조 설계
- SAS `OAuth2TokenEndpointFilter` 참고

---

## 4월 12일 (화) — Filter + Converter 구현

- `/oauth2/token` 요청 Filter 처리
- `AuthorizationCodeTokenRequest` Converter 연결

---

## 4월 13일 (수) — Provider 연결 + E2E 테스트

- Filter → Provider 위임
- `TokenEndPointE2ETest` 통과 확인

---

## 4월 14일 (목) — 오류 응답 강화

- `error_description` 추가
- `error_uri` 추가
- 공통 에러 처리 구조 정리

---

## 4월 15일 (금) — code lifecycle 강화

- `issuedAt` / `expiresAt` 검증
- 재사용 방지
- 만료 처리 정책 + 테스트

---

## 4월 16일 (토) — 실패 케이스 확대

- `invalid_request` / `invalid_client` / `invalid_grant` / `unsupported_grant_type`
- token E2E 시나리오 표 작성

---

# 4주차 — 테스트 / 문서화

## 4월 17일 (월)

- authorize E2E 시나리오 최종 정리
    - 정상 / 실패 / redirect 여부 / error 코드 / state 포함 여부

---

## 4월 18일 (화)

- token E2E 시나리오 최종 정리
    - authorization_code 흐름
    - invalid_client / invalid_grant

---

## 4월 19일 (수)

- 정상 / 실패 케이스 RFC 6749 기준 대조 정리

---

## 4월 20일 (목)

- validator / unit / integration / e2e 테스트 구분 문서화

---

## 4월 21일 (금)

- 구조 그림 정리
    - v2 구조 (Controller-adapter)
    - v3 구조 (Filter-based)
    - v2 → v3 전환 흐름

---

## 4월 22일 (토) 

- README 정리
- `./gradlew test` 전체 실행
- 구조 / 테스트 / 문서 최종 점검
---

# 우선순위

## 반드시
- 토큰 엔드포인트 v2 완성 (작업 2-1 ~ 2-5)
- v3 Filter → Converter → Provider 구조 전환
- authorization_code 교환 흐름
- code 1회용 / 만료 처리
- E2E 시나리오 검증

## 하면 좋음
- `error_description` / `error_uri`
- 테스트 전략 문서

## 선택
- refresh token (v3 완료 후 별도 검토)
- 구조 그림 고급화

---

# 주간 목표 요약

- **1주차**: 토큰 엔드포인트 v2 완성
- **2주차**: 인가 엔드포인트 v3 (Filter 기반)
- **3주차**: 토큰 엔드포인트 v3 + 오류/lifecycle 강화
- **4주차**: 테스트 / 문서화
