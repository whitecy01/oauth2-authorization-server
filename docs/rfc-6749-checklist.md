# RFC 6749 Checklist

이 문서는 RFC 6749 요구사항을 구현 체크리스트로 분해한 문서다.

- 목적: RFC 요구사항 누락 없이 구현 범위를 추적
- 기준: RFC 6749 핵심 요구사항 중심
- 원칙: RFC 조항은 체크리스트로 관리하고, 실제 검증은 코드와 테스트로 보장

## Status

- `Not Started`: 아직 구현하지 않음
- `Temporary`: 임시 구현만 존재함
- `Implemented`: 요구사항을 구현함
- `Refactored`: 구조를 정리해 책임 분리를 마침
- `Tested`: 테스트로 검증함

## Authorization Endpoint

### Authorization Request Validation

- [ ] `response_type` 필수 검증
  Status: `Not Started`
- [ ] 지원하지 않는 `response_type` 거부
  Status: `Not Started`
- [ ] `client_id` 필수 검증
  Status: `Not Started`
- [ ] 등록되지 않은 client 거부
  Status: `Not Started`
- [ ] 비활성 또는 사용 불가 client 거부
  Status: `Not Started`
- [ ] client별 허용 `redirect_uri` 검증
  Status: `Not Started`
- [ ] 요청 `redirect_uri`와 등록값 일치 여부 검증
  Status: `Not Started`
- [ ] 요청 `scope` 유효성 검증
  Status: `Not Started`
- [ ] client별 허용 scope 범위 검증
  Status: `Not Started`
- [ ] `state` 전달 및 응답 반영
  Status: `Not Started`

### Authorization Consent And Code Issuance

- [ ] 로그인 사용자 기준으로 인가 처리
  Status: `Not Started`
- [ ] authorization code 발급
  Status: `Not Started`
- [ ] authorization code에 client 정보 바인딩
  Status: `Not Started`
- [ ] authorization code에 redirect URI 바인딩
  Status: `Not Started`
- [ ] authorization code에 scope 바인딩
  Status: `Not Started`
- [ ] authorization code 만료 시간 적용
  Status: `Not Started`
- [ ] authorization code 일회성 사용 보장
  Status: `Not Started`

### Authorization Error Handling

- [ ] `invalid_request` 처리
  Status: `Not Started`
- [ ] `unauthorized_client` 처리
  Status: `Not Started`
- [ ] `unsupported_response_type` 처리
  Status: `Not Started`
- [ ] `invalid_scope` 처리
  Status: `Not Started`
- [ ] redirect 기반 에러 응답 시 `state` 유지
  Status: `Not Started`

## Token Endpoint

### Client Authentication

- [ ] confidential client 인증 처리
  Status: `Not Started`
- [ ] `client_secret` 검증
  Status: `Not Started`
- [ ] 인증 실패 시 token 발급 차단
  Status: `Not Started`
- [ ] public client와 confidential client 동작 분리
  Status: `Not Started`

### Authorization Code Grant Validation

- [ ] `grant_type` 필수 검증
  Status: `Not Started`
- [ ] `grant_type=authorization_code` 처리
  Status: `Not Started`
- [ ] `code` 필수 검증
  Status: `Not Started`
- [ ] 존재하지 않는 authorization code 거부
  Status: `Not Started`
- [ ] 만료된 authorization code 거부
  Status: `Not Started`
- [ ] 이미 사용된 authorization code 거부
  Status: `Not Started`
- [ ] authorization code와 client 일치 여부 검증
  Status: `Not Started`
- [ ] authorization code와 `redirect_uri` 일치 여부 검증
  Status: `Not Started`

### Token Issuance

- [ ] access token 발급
  Status: `Not Started`
- [ ] token type을 `Bearer`로 반환
  Status: `Not Started`
- [ ] `expires_in` 반환
  Status: `Not Started`
- [ ] 인가된 scope만 반영
  Status: `Not Started`
- [ ] token 응답에 cache 방지 헤더 적용
  Status: `Not Started`

### Token Error Handling

- [ ] `invalid_request` 처리
  Status: `Not Started`
- [ ] `invalid_client` 처리
  Status: `Not Started`
- [ ] `invalid_grant` 처리
  Status: `Not Started`
- [ ] `unauthorized_client` 처리
  Status: `Not Started`
- [ ] `unsupported_grant_type` 처리
  Status: `Not Started`
- [ ] `invalid_scope` 처리
  Status: `Not Started`

## Token And Resource Access

- [ ] bearer token으로 보호 API 접근 처리
  Status: `Not Started`
- [ ] 유효하지 않은 token 거부
  Status: `Not Started`
- [ ] 만료된 token 거부
  Status: `Not Started`
- [ ] token 기반 사용자 식별 처리
  Status: `Not Started`

## Testing Strategy

### Unit Tests

- [ ] client 검증 로직 테스트
- [ ] redirect URI 검증 로직 테스트
- [ ] authorization request 파라미터 검증 테스트
- [ ] authorization code 검증 테스트
- [ ] token request 파라미터 검증 테스트
- [ ] scope 검증 테스트
- [ ] token 발급 정책 테스트
- [ ] 에러 코드 매핑 테스트

### Integration Tests

- [ ] `/oauth2/authorize` 정상 요청 테스트
- [ ] `/oauth2/authorize` 에러 응답 테스트
- [ ] `/oauth2/token` 정상 요청 테스트
- [ ] `/oauth2/token` 에러 응답 테스트
- [ ] 보호 API bearer token 인증 테스트

## Notes

- 현재 상태 값은 초기값으로 모두 `Not Started`로 둔다.
- 구현이 진행되면 각 항목의 상태를 `Temporary`, `Implemented`, `Refactored`, `Tested`로 갱신한다.
- `Spring Authorization Server`를 참고해 구조를 바꿀 때도 체크리스트 항목은 유지하고 상태만 갱신한다.
