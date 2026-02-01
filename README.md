# OAuth2 Authorization Server (RFC 6749 Implementation)

본 프로젝트는 **OAuth2 Authorization Server**를 직접 구현함으로써  
OAuth2 프로토콜의 내부 동작 원리와 보안 요구사항을 깊이 이해하는 것을 목표로 한다.

Spring Security는 **사용자 로그인 및 세션 관리 보조 도구**로만 활용하며,  
OAuth2 인가 및 토큰 발급 로직은 **RFC 문서를 기준으로 직접 설계·구현**한다.

> 본 프로젝트에서는 **Spring Authorization Server를 사용하지 않는다.**  
> (구조와 동작 방식은 참고만 한다)

## 📌 프로젝트 목표

- OAuth2 표준(RFC 6749 및 관련 RFC)을 직접 구현
- Authorization Code Grant Flow 이해 및 구현
- OAuth2 Authorization Server의 내부 동작 구조 학습
- Spring Security의 실제 역할(인증/세션) 명확히 분리
- “사용”이 아닌 “구현” 중심의 OAuth2 학습

## 📚 RFC 문서 번역 및 학습 자료

본 프로젝트는 직접 RFC 문서 번역 및 정리를 기반으로 설계되었다.

- 🔗 **OAuth RFC 번역 저장소**  
  https://github.com/whitecy01/codyssey/tree/main/RFC/OAuth


## 🧩 프로젝트 범위 (Scope)

### 포함
- OAuth2 Authorization Code Grant
- Confidential Client 지원
- `/oauth2/authorize` 엔드포인트 구현
- `/oauth2/token` 엔드포인트 구현
- Authorization Code 발급 및 검증
- Access Token(Opaque Token) 발급
- Bearer Token 기반 보호 API
- Spring Security 기반 로그인 + 세션

### 제외 (추후 추가 예정)
- PKCE (RFC 7636)
- Public Client (SPA / Mobile)
- Refresh Token
- OpenID Connect
- Spring Authorization Server 사용

## 🏗️ 기술 스택
- **Java 21**
- **Spring Boot**
- **Spring Security**
- **Spring Web**
- **Spring Data JPA**
- **PostgreSQL**
- Gradle


## 🔐 인증 구조 개요

- 사용자 인증(Authentication)
    - Spring Security Form Login
    - 세션 기반 인증 유지

- OAuth2 인가(Authorization)
    - RFC 6749 기반 직접 구현
    - Authorization Code → Access Token 교환

Spring Security는 **OAuth2 로직을 담당하지 않으며**, 인가 서버의 인증 인프라 역할만 수행한다.

## 🗺️ 구현 단계 개요

본 프로젝트는 다음 단계로 구현된다.

1. 인증 인프라 구성 (Spring Security 로그인/세션)
2. OAuth Client 등록 및 검증
3. Authorization Endpoint 구현 (Code 발급)
4. Token Endpoint 구현 (Token 발급)
5. 보호 API 및 Bearer Token 검증

각 단계는 GitHub Project / Issue 단위로 관리된다.

