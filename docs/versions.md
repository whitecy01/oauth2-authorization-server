# Versions

이 문서는 버전별 목표와 리팩터링 방향을 관리한다.

## Version Policy

- `v0`: 학습 목적의 임시 구현
- `v1`: RFC 6749 핵심 요구사항 검증 강화
- `v2`: 구조 리팩터링
- `v3`: 확장 스펙 및 운영 관점 보완

## v0

### Goal

- OAuth2 Authorization Server의 기본 흐름 이해
- Authorization Code Grant 최소 구현
- 로그인, 인가, 토큰 발급 흐름 연결

### Characteristics

- 임시 구현 허용
- 구조보다 동작 확인 우선
- RFC 요구사항 일부 누락 가능

### Exit Criteria

- `/oauth2/authorize`와 `/oauth2/token` 최소 동작
- authorization code 발급과 교환 흐름 확인
- 보호 API에서 bearer token 기반 인증 확인

## v1

### Goal

- RFC 6749 핵심 요구사항을 명시적으로 검증
- 구현 누락을 체크리스트 기반으로 보완
- 유닛 테스트와 통합 테스트 추가

### Focus

- client 검증
- redirect URI 검증
- response type 및 grant type 검증
- scope 검증
- authorization code 검증
- RFC 에러 응답 처리

### Exit Criteria

- [RFC 6749 체크리스트](/Users/jeongjaeyoon/Documents/GitHub/oauth2-authorization-server/docs/rfc-6749-checklist.md) 핵심 항목이 `Implemented` 이상
- 핵심 validator/service 로직 유닛 테스트 확보
- authorize/token 엔드포인트 통합 테스트 확보

## v2

### Goal

- `Spring Authorization Server`를 참고해 현재 구조를 재정리
- 인증, 인가, 토큰 발급 책임을 명확히 분리
- 임시 구현 제거

### Focus

- request validation 책임 분리
- domain/service/provider 계층 정리
- authorization code 및 token 처리 모델 재구성
- 에러 처리 구조 일관화

### Reference Direction

- `Spring Authorization Server`를 그대로 복제하지는 않음
- 다만 내부 구성 방식, 책임 분리, 객체 역할은 적극적으로 참고
- 최종 목적은 구현 이해도와 유지보수성 향상

### Exit Criteria

- 핵심 흐름에서 임시 코드 제거
- 주요 컴포넌트 책임이 명확해짐
- 테스트가 구조 변경 이후에도 유지됨

## v3

### Goal

- 확장 스펙 반영과 운영 관점 보완

### Candidates

- PKCE
- Refresh Token
- Public Client 지원
- OpenID Connect 확장 검토
- 토큰 저장소 및 만료 정책 고도화
- 감사 로그 및 보안 이벤트 추적

### Exit Criteria

- 우선순위가 높은 확장 스펙 반영
- 보안 정책과 토큰 수명 정책 정리
- 운영 시나리오 기준 테스트 보완

## Working Rule

- 새 기능을 추가하기 전에 먼저 어느 버전에 속하는지 기록한다.
- 구현 후에는 체크리스트 상태와 버전 문서를 함께 갱신한다.
- 구조 변경이 큰 경우에는 `v2` 기준으로 설계 이유를 짧게 남긴다.
