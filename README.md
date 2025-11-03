# Auth Service

[![CI](https://github.com/yjincode/ensemblely_auth/actions/workflows/ci.yml/badge.svg)](https://github.com/yjincode/ensemblely_auth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/yjincode/ensemblely_auth/branch/main/graph/badge.svg)](https://codecov.io/gh/yjincode/ensemblely_auth)

앙상블리 프로젝트의 사용자 인증 및 회원 관리 서비스입니다.

## 🏗 아키텍처 개요

```
클라이언트
    ↓ (Access Token in Header, Refresh Token in Cookie)
게이트웨이
    ↓ gRPC (토큰 검증)
Auth Service ←→ 다른 마이크로서비스 (gRPC)
    ↓
PostgreSQL + Redis
```

**포트 구성**
- **REST API**: 9001 (클라이언트 ↔ 게이트웨이 ↔ Auth Service)
- **gRPC**: 9090 (마이크로서비스 간 통신)

### 핵심 설계 원칙

1. **게이트웨이 중심 인증**
   - 모든 클라이언트 요청은 게이트웨이를 거침
   - 게이트웨이가 gRPC로 Auth Service에 토큰 검증 요청
   - Auth Service는 순수 비즈니스 로직만 담당 (필터 없음)

2. **JWT 토큰 전략**
   - **Access Token** (30분): Authorization 헤더, userId + nickname claim 포함
   - **Refresh Token** (14일): HttpOnly 쿠키, 세션 DB 관리
   - 본인 닉네임: 프론트엔드가 토큰 파싱 → Context 저장 (서버 조회 불필요)
   - 다른 사람 닉네임: gRPC UserInfoService로 실시간 조회

3. **세션 관리 (이중화)**
   - **Redis (AOF)**: 블랙리스트 토큰 고속 검증 + 영속성 보장
   - **PostgreSQL**: 세션 메타데이터 (디바이스, IP, 국가, 마지막 사용 시각)
   - 로그아웃/세션 무효화 시 Redis + DB 동시 처리

4. **마이크로서비스 간 통신**
   - gRPC 기반 고성능 서버 간 통신
   - 팀 서비스 등이 유저 정보 조회 시 UserInfoService 호출
   - 인증은 게이트웨이에서 이미 처리되므로 권한 체크 불필요

## 🚀 주요 기능

### 인증 & 회원가입
- ✅ 이메일 기반 회원가입
- ✅ 로그인 및 JWT 토큰 발급 (Access + Refresh)
- ✅ 아이디 중복 체크
- ✅ 비밀번호 재설정
- ✅ 토큰 재발급 (Access Token 만료 시)
- ✅ 로그아웃 (세션 무효화)

### 이메일 인증
- ✅ 6자리 인증 코드 발송
- ✅ 원클릭 이메일 인증 링크
- ✅ 5분 TTL 자동 만료
- ✅ Rate Limiting (1분 1회, 하루 10회)
- ✅ Redis 기반 코드 저장

### 세션 관리
- ✅ 다중 디바이스 세션 관리
- ✅ 세션 목록 조회 (디바이스명, IP, 국가, 마지막 사용 시각)
- ✅ 특정 세션 무효화
- ✅ 전체 세션 무효화 (비밀번호 변경 시)
- ✅ 세션 자동 정리 배치 (14일 이상 미사용)
- ✅ IP 암호화 저장 (개인정보 보호)

### 보안 감사 로그
- ✅ 세션 생성/무효화 이벤트 자동 기록
- ✅ 토큰 갱신 이력 추적
- ✅ 비동기 로그 저장 (메인 로직 성능 영향 없음)
- ✅ IP, 디바이스, 국가 정보 포함

### gRPC 서비스 (포트 9090)

#### 1. TokenService (게이트웨이용)
- `ValidateRefreshToken`: 토큰 검증 + Access Token 재발급
  - ValidationLevel: `BASIC` (인증만) / `WITH_USER_ID` (userId 포함)
  - Access Token 만료 시 Refresh Token으로 자동 재발급
- `RefreshAccessToken`: Access Token 재발급
- `Logout`: 세션 무효화

#### 2. UserInfoService (마이크로서비스용)
- `GetUserNickname`: 단일 사용자 닉네임 조회
- `GetUserNicknames`: 일괄 닉네임 조회
- `GetUserMaxWorkspaces`: 워크스페이스 생성 제한 조회
- `GetUserDisplayInfo`: 닉네임 + 프로필 이미지 조회

## 🛠 기술 스택

- **Java 21** + **Spring Boot 3.5.6**
- **PostgreSQL** - 사용자 데이터, 세션, 감사 로그
- **Redis (AOF)** - 이메일 인증 코드, 블랙리스트 토큰 (영속성)
- **gRPC** - 마이크로서비스 간 통신
- **JWT (JJWT)** - 토큰 기반 인증
- **Thymeleaf** - 이메일 템플릿
- **JaCoCo** - 코드 커버리지
- **GeoLite2** - IP 기반 국가 확인

## 📦 프로젝트 구조

```
src/main/java/spring/authservice/
├── config/          # 설정 (Security, Redis, JWT)
│   ├── SecurityConfig.java       # Spring Security (모든 요청 허용)
│   ├── RedisConfig.java          # Redis AOF 설정
│   └── JwtProperties.java        # JWT 설정 값
├── domain/          # Entity & DTO
│   ├── User.java                 # 사용자 엔티티
│   ├── RefreshTokenSession.java # 세션 엔티티
│   ├── SecurityAuditLog.java    # 감사 로그 엔티티
│   └── AuditEventType.java      # 감사 이벤트 타입
├── grpc/            # gRPC 서비스 구현
│   ├── TokenServiceGrpcImpl.java      # 토큰 검증 서비스
│   └── UserInfoGrpcServiceImpl.java   # 유저 정보 조회 서비스
├── service/         # 비즈니스 로직
│   ├── UserService.java               # 회원 가입/로그인/토큰 관리
│   ├── EmailService.java              # 이메일 발송
│   ├── RefreshTokenSessionService.java # 세션 관리
│   ├── RefreshTokenBlacklistService.java # 블랙리스트 관리
│   ├── SecurityAuditService.java      # 감사 로그
│   └── GeoIpService.java              # IP → 국가 코드
├── scheduler/       # 배치 작업
│   └── SessionCleanupScheduler.java   # 세션 자동 정리
├── util/            # 유틸리티
│   ├── JwtUtil.java           # JWT 생성/검증
│   ├── CryptoUtil.java        # 토큰 암호화/IP 암호화
│   └── PasswordValidator.java # 비밀번호 검증
└── web/             # REST API 컨트롤러
    └── UserController.java    # 인증 API

src/main/proto/      # gRPC 프로토콜 정의
└── user_info.proto  # TokenService + UserInfoService 정의

src/main/resources/
├── templates/       # 이메일 템플릿
└── application.yml  # 설정 파일
```

## 🔧 환경 설정

### 1. 로컬 설정 파일 생성

`src/main/resources/application-local.yml` 파일을 생성하세요:

```yaml
server:
  port: 9001  # REST API 포트

grpc:
  server:
    port: 9090  # gRPC 포트

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/auth_db
    username: your-username
    password: your-password

  mail:
    username: your-email@gmail.com
    password: your-app-password  # Gmail 앱 비밀번호

  data:
    redis:
      host: localhost
      port: 6379

jwt:
  secret-key: your-jwt-secret-key
  issuer: ensemblely-auth
```

### 2. 필요한 서비스 실행

```bash
# PostgreSQL
docker run -d \
  --name auth-postgres \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=admin \
  -e POSTGRES_PASSWORD=admin123 \
  -p 5432:5432 \
  postgres:15

# Redis (AOF 활성화)
docker run -d \
  --name auth-redis \
  -p 6379:6379 \
  -v redis-data:/data \
  redis:7 \
  redis-server --appendonly yes
```

### 3. Gmail 앱 비밀번호 발급

1. Google 계정 > 보안 > 2단계 인증 활성화
2. 앱 비밀번호 생성
3. `application-local.yml`에 설정

## 🚀 실행 방법

```bash
# 빌드 (proto 파일 자동 생성)
./gradlew build

# 테스트
./gradlew test

# 실행
./gradlew bootRun
# → REST API: http://localhost:9001
# → gRPC: localhost:9090

# proto만 재생성
./gradlew generateProto
```

## 📊 테스트 & 커버리지

```bash
# 테스트 실행
./gradlew test

# 커버리지 리포트 생성
./gradlew jacocoTestReport

# 커버리지 검증 (최소 80%)
./gradlew jacocoTestCoverageVerification
```

**현재 커버리지:**
- Controller: 100% ✅
- 목표: 80% 이상

## 📡 API 엔드포인트

**Base URL:** `http://localhost:9001` (개발 환경)

> **참고:** 모든 클라이언트 요청은 게이트웨이를 거칩니다. 직접 호출은 개발 환경에서만 사용하세요.

### 회원가입 & 로그인
```http
POST /auths/register
POST /auths/login
GET  /auths/check-userid?userId={userId}
```

### 이메일 인증
```http
POST /auths/email/send-verification
POST /auths/email/verify-code
GET  /auths/verify-email?token={token}
```

### 비밀번호 재설정
```http
POST /auths/password/reset/send
POST /auths/password/reset/verify
POST /auths/password/reset/change
```

### 토큰 관리 (인증 필요)
```http
POST /auths/refresh      # Access Token 재발급
POST /auths/logout       # 로그아웃
```

### 세션 관리 (인증 필요)
```http
GET    /me/sessions              # 세션 목록 조회
DELETE /me/sessions/{sessionId}  # 특정 세션 무효화
DELETE /me/sessions              # 모든 세션 무효화
```

### gRPC (포트 9090)

#### TokenService (게이트웨이용)
```protobuf
rpc ValidateRefreshToken(ValidateTokenRequest) returns (ValidateTokenResponse);
rpc RefreshAccessToken(RefreshTokenRequest) returns (RefreshTokenResponse);
rpc Logout(LogoutRequest) returns (LogoutResponse);

enum ValidationLevel {
  BASIC = 0;         // 인증만
  WITH_USER_ID = 1;  // 인증 + userId
}
```

#### UserInfoService (마이크로서비스용)
```protobuf
rpc GetUserNickname(UserIdRequest) returns (UserNicknameResponse);
rpc GetUserNicknames(UserIdsRequest) returns (UserNicknamesResponse);
rpc GetUserMaxWorkspaces(UserIdRequest) returns (UserMaxWorkspacesResponse);
rpc GetUserDisplayInfo(UserIdRequest) returns (UserDisplayInfoResponse);
```

## 🔐 보안

### 토큰 보안
- ✅ BCrypt 비밀번호 암호화 (strength 10)
- ✅ JWT Access Token (30분 만료)
- ✅ Refresh Token 세션 관리 (14일 만료)
- ✅ HttpOnly 쿠키로 Refresh Token 전송 (XSS 방지)
- ✅ 블랙리스트 토큰 자동 검증 (Redis AOF)

### 데이터 보호
- ✅ Refresh Token AES-256 암호화 저장
- ✅ IP 주소 AES-256 암호화 저장
- ✅ SHA-256 토큰 해싱 (빠른 조회용)
- ✅ 환경변수 기반 민감정보 관리

### 악용 방지
- ✅ 이메일 발송 Rate Limiting (1분 1회, 하루 10회)
- ✅ 세션 자동 정리 (14일 미사용 시 삭제)
- ✅ 보안 감사 로그 자동 기록
- ✅ GeoIP 기반 이상 로그인 탐지 가능

## 📝 개발 가이드

### User 엔티티 필드
- `userId`: 로그인 아이디 (고유)
- `email`: 이메일 (인증 필수)
- `nickname`: 닉네임 (Access Token claim에 포함)
- `password`: BCrypt 암호화된 비밀번호
- `profileImageUrl`: 프로필 이미지 URL
- `authProvider`: 인증 제공자 (EMAIL, GOOGLE, KAKAO 등)
- `accountVerified`: 이메일 인증 여부
- `maxWorkspaces`: 생성 가능한 워크스페이스 수 (기본 2개)

### RefreshTokenSession 엔티티
- `sessionId`: UUID (세션 고유 ID)
- `userId`: 사용자 ID
- `refreshTokenHash`: SHA-256 해시 (빠른 조회)
- `encryptedToken`: AES-256 암호화된 토큰
- `deviceName`: 디바이스명 (User-Agent 파싱)
- `ipAddress`: 암호화된 IP 주소
- `country`: 국가 코드 (GeoIP)
- `createdAt`: 생성 시각
- `lastUsedAt`: 마지막 사용 시각

### SecurityAuditLog 이벤트 타입
- `SESSION_CREATED`: 로그인 (세션 생성)
- `SESSION_REVOKED`: 로그아웃 (특정 세션 무효화)
- `ALL_SESSIONS_REVOKED`: 전체 로그아웃 (비밀번호 변경 등)
- `SESSION_REVOKED_BY_TOKEN`: 토큰으로 세션 무효화
- `TOKEN_REFRESHED`: Access Token 재발급

### 게이트웨이 연동 예시

```java
// 게이트웨이에서 토큰 검증
ValidateTokenRequest request = ValidateTokenRequest.newBuilder()
    .setAccessToken(accessToken)
    .setRefreshToken(refreshToken)
    .setLevel(ValidationLevel.WITH_USER_ID)
    .build();

ValidateTokenResponse response = tokenServiceStub.validateRefreshToken(request);

if (response.getValid()) {
    Long userId = response.getUserId();

    // 새 Access Token 발급된 경우
    if (!response.getNewAccessToken().isEmpty()) {
        // 클라이언트에 새 토큰 전달
    }

    // userId를 헤더에 담아 각 서비스로 라우팅
    exchange.getRequest().mutate()
        .header("X-User-Id", userId.toString())
        .build();
}
```

### 팀 서비스에서 유저 정보 조회 예시

```java
// 팀원 목록 조회 (gRPC)
UserIdsRequest request = UserIdsRequest.newBuilder()
    .addAllUserIds(Arrays.asList(1L, 2L, 3L))
    .build();

UserNicknamesResponse response = userInfoServiceStub.getUserNicknames(request);

for (UserNicknameResponse user : response.getUsersList()) {
    if (user.getExists()) {
        System.out.println(user.getUserId() + ": " + user.getNickname());
    }
}
```

### 이메일 템플릿 커스터마이징
`src/main/resources/templates/` 디렉토리의 HTML 파일을 수정하세요:
- `email-verification.html` - 이메일 인증
- `password-reset-email.html` - 비밀번호 재설정

## 🔄 배치 작업

### SessionCleanupScheduler
- **실행 주기:** 매일 새벽 3시
- **작업 내용:** 14일 이상 미사용 세션 자동 삭제
- **동작:** Redis 블랙리스트 + DB 세션 동시 정리

## 📈 모니터링

### 주요 로그
- 세션 생성/무효화 이벤트
- 토큰 재발급 이력
- 이메일 발송 성공/실패
- gRPC 호출 로그

### 성능 지표
- gRPC 응답 시간 (평균 < 100ms)
- Redis 조회 성능 (블랙리스트 검증)
- 세션 DB 조회 성능

## 🐛 트러블슈팅

### Redis AOF 파일이 커질 때
```bash
# Redis CLI에서 AOF 재작성
redis-cli BGREWRITEAOF
```

### GeoIP 데이터베이스 업데이트
```bash
# GeoLite2 데이터베이스를 최신 버전으로 교체
# src/main/resources/GeoLite2-Country.mmdb
```

### gRPC 코드 생성 오류
```bash
# proto 파일 수정 후 재생성
./gradlew clean generateProto
```

## 📚 참고 자료

- [Spring Boot Security](https://spring.io/projects/spring-boot)
- [gRPC Java](https://grpc.io/docs/languages/java/)
- [JJWT](https://github.com/jwtk/jjwt)
- [Redis AOF](https://redis.io/docs/management/persistence/)

## 📄 라이선스

MIT License
