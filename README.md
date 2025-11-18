# Auth Service

[![CI](https://github.com/yjincode/ensemblely_auth/actions/workflows/ci.yml/badge.svg)](https://github.com/yjincode/ensemblely_auth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/yjincode/ensemblely_auth/branch/main/graph/badge.svg)](https://codecov.io/gh/yjincode/ensemblely_auth)

앙상블리 플랫폼에서 인증, 회원, 세션, 프로필 전반을 담당하는 백엔드 서비스입니다. 모바일/웹 클라이언트는 게이트웨이를 거쳐 REST API를 호출하고, 다른 마이크로서비스는 gRPC로 사용자 정보를 조회합니다.

## 🏗 Architecture
```
[Mobile / Web]
     │  (Access Token Header, Refresh Cookie)
     ▼
[API Gateway]───────┐
     │ gRPC         │
     ▼              │
[Auth Service]◀─────┘
  │   │   │   │
  │   │   │   ├─🔐 Redis (AOF, Pub/Sub)
  │   │   ├─────🗄 PostgreSQL
  │   ├──────────☁️ AWS S3 (프로필)
  └───────────────🌏 External OAuth / GeoIP
```
- REST API: `:9001`
- Internal gRPC: `:9090`
- Session metadata: PostgreSQL
- Tokens + email verification + SSE pub/sub: Redis
- Profile assets: AWS S3

## ✨ Capabilities
- 이메일 기반 회원가입 및 로그인, 실시간 이메일 인증(SSE) + 코드/링크 병행 제공
- JWT 발급/갱신, Refresh Token 세션 관리, Redis 블랙리스트, GeoIP 기반 세션 정보 추적
- 비밀번호 초기화/변경, 강력한 규칙 검사, 로그인 이력 기반 세션 강제 만료
- 소셜 로그인(Naver/Kakao/Google)과 기존 계정 통합 플로우, 임시 머지 토큰 Redis 저장
- S3 기반 프로필 이미지 업로드/삭제, 허용 확장자 및 용량 검사, 파일 교체 시 기존 파일 정리
- gRPC TokenService(UserId 전달/재발급/로그아웃) 및 UserInfoService(닉네임·프로필 조회)
- 매일 새벽 세션 정리 배치, 이메일 발송 rate limit, 감사 로그 기록, JaCoCo 기반 커버리지

## 🧱 Tech Stack
- **Runtime**: Java 21, Spring Boot 3.5, Spring Security, Spring Data JPA
- **Data**: PostgreSQL, Redis (AOF + Pub/Sub), AWS S3, Thymeleaf templates
- **Protocols**: REST, gRPC (blocking + reactive stub), SSE
- **Auth**: JWT(JJWT), BCrypt, AES-256 + HMAC 서명, GeoLite2
- **Build/Test**: Gradle, JaCoCo, GitHub Actions, Codecov

## 📁 Directory Layout
```
src/main/java/spring/authservice
├── AuthServiceApplication.java
├── adapter
│   ├── in
│   │   ├── web/              # REST + SSE controllers
│   │   └── grpc/             # TokenService, UserInfoService
│   └── out
│       ├── cache/            # Redis token cache
│       ├── persistence/      # Spring Data JPA adapters
│       ├── storage/          # S3 profile storage
│       ├── notification/     # Email sender
│       └── external/         # GeoIP client
├── application
│   ├── port/{in,out}/        # Hexagonal ports
│   └── service/              # User, Session, Email, Social, Profile services
├── config/                   # Security, Redis, S3, JWT, OAuth
├── domain/{model,vo}/        # Entities + DTOs
├── scheduler/                # SessionCleanupScheduler
├── util/                     # Crypto/JWT helpers
└── resources
    ├── application*.yml      # Profile-based config
    ├── templates/            # Email HTML
    └── proto/user_info.proto # gRPC contracts
```

### Layer Highlights
- **Adapters In**: `UserController`, `EmailVerificationSseController`, gRPC `TokenServiceGrpcImpl`, `UserInfoGrpcServiceImpl`
- **Application Services**: registration/login(UserService), token/session(RefreshTokenSessionService, RefreshTokenBlacklistService), email(EmailService, EmailVerificationSseService), profile(ProfileService), social login adapters (Google/Kakao/Naver)
- **Adapters Out**: persistence adapters bridging ports to `UserRepository` & `RefreshTokenSessionRepository`, `TokenCacheAdapter` for Redis blacklists, `EmailAdapter` for JavaMail + Thymeleaf, `S3StorageAdapter` for AWS SDK v2

## 🧪 Local Development
1. **Prerequisites**: JDK 21, Docker (for PostgreSQL/Redis), AWS/SNS credentials for S3 if 이미지 업로드 테스트, SMTP 계정.
2. **Boot services**
   ```bash
   docker compose up -d   # postgres:5432, redis:6379
   ```
3. **Configure secrets**: copy `src/main/resources/application-local.yml` and override DB, Redis, OAuth, S3, SMTP, JWT, AES/HMAC keys.
4. **Run**
   ```bash
   ./gradlew bootRun      # REST :9001, gRPC :9090
   ```
5. **Build/Test**
   ```bash
   ./gradlew build        # includes proto generation
   ./gradlew test
   ./gradlew jacocoTestReport jacocoTestCoverageVerification
   ```
6. **Proto only**
   ```bash
   ./gradlew generateProto
   ```

## 🌐 REST & SSE API
_Base URL: http://localhost:9001 (개발 환경에서만 직접 호출)_

| 구분 | Endpoint | 설명 |
| --- | --- | --- |
| 인증 | `POST /auths/register` | 이메일 회원가입 + 자동 로그인 |
|  | `POST /auths/login` | 이메일 로그인 |
|  | `POST /auths/logout` | Refresh Token 기반 로그아웃 |
| 이메일 | `POST /auths/email/send-verification` | 인증 메일 발송 (code + link) |
|  | `POST /auths/email/verify-code` | 6자리 코드 검증 |
|  | `GET /auths/verify-email?token=...` | 인증 토큰으로 HTML 결과 제공 |
| 비밀번호 | `POST /auths/password/reset/send` | 재설정 코드 발송 |
|  | `POST /auths/password/reset/verify` | 코드 검증 |
|  | `POST /auths/password/reset` | 새 비밀번호 설정 |
| 소셜 | `POST /auths/social/login` | Naver/Kakao/Google Authorization Code 로그인 |
|  | `POST /auths/social/merge` | 기존 계정과 통합/신규 분기 |
| 세션 | `GET /me/sessions` | X-User-Id 헤더 기준 세션 목록 |
|  | `DELETE /me/sessions/{sessionId}` | 특정 디바이스 만료 |
|  | `DELETE /me/sessions` | 전체 세션 만료 |
| 프로필 | `PUT /me/password` | 로그인 상태 비밀번호 변경 |
|  | `POST /me/profile/image` | Multipart 프로필 업로드 |
|  | `DELETE /me/profile/image` | 프로필 이미지 삭제 |
| SSE | `GET /api/auth/verify-stream?email=` | 이메일 인증 결과 실시간 수신 |
| 모니터링 | `GET /api/auth/verify-stream/count` | 활성 SSE 커넥션 수 |

## 🔌 gRPC Contracts (`src/main/proto/user_info.proto`)
- **TokenService**
  - `ValidateRefreshToken(ValidateTokenRequest)`: Access 우선 검증, 만료 시 Refresh로 재발급, `ValidationLevel`에 따라 userId 반환
  - `RefreshAccessToken(RefreshTokenRequest)`: Refresh 토큰 그대로 재사용
  - `Logout(LogoutRequest)`: Refresh 토큰 기반 세션 무효화
- **UserInfoService**
  - `GetUserNickname(UserIdRequest)`
  - `GetUserNicknames(UserIdsRequest)`
  - `GetUserDisplayInfo(UserIdRequest)` (닉네임 + 프로필 이미지 URL)

게이트웨이는 `ValidateTokenRequest.level = WITH_USER_ID` 로 호출하여 userId를 헤더(`X-User-Id`)에 주입합니다. 내부 서비스는 `UserInfoService`로 닉네임/프로필을 일괄 조회합니다.

## 🗃 Domain Model
- `User`
  - `id`, `email`, `username`, `nickname`, `password`, `authProvider`, `accountVerified`, `profileImageUrl`
  - OAuth 프로필 합치기, 프로필 이미지 교체, 비밀번호 변경 시 해시 재생성
- `RefreshTokenSession`
  - `sessionId`, `userId`, `refreshTokenHash`, `encryptedToken`, `deviceName`, `ipAddress`, `country`, `createdAt`, `lastUsedAt`
  - 로그인, 토큰 갱신, 로그아웃 시 동기화, 14일 미사용 자동 삭제
- `UserDto`
  - 회원가입/로그인/소셜/세션/비밀번호/프로필 관련 request·response DTO를 한곳에서 관리

## 🔐 Security & Reliability
- JWT Access(30분) + Refresh(14일) 발급, SHA-256 + AES-256(IV 포함) 복합 보호
- HttpOnly Secure 쿠키를 통해 Refresh Token 전달, Access Token은 헤더 사용
- Redis 블랙리스트(로그아웃·탈취 대응), Refresh Token 마지막 사용 시각 업데이트
- BCrypt 비밀번호 해시, PasswordValidator로 길이/조합 검사, 재사용 방지
- 이메일 인증 Rate Limit (1분 1회/하루 10회), 실패 시에도 재시도 여지 부여
- SSE + Redis Pub/Sub으로 인증 완료 즉시 프론트 전달
- GeoIP 기반 국가 기록, SessionCleanupScheduler(매일 03:00)로 장기 미사용 세션 삭제
- JaCoCo 리포트(`build/reports/jacoco/test/html/index.html`), 최소 17% 커버리지 규칙 설정 (proto/설정 제외)

## 📈 Observability & Ops
- Logback 설정(`src/main/resources/logback-spring.xml`)로 REST/gRPC/메일/세션/토큰 로그 분리
- `logs/` 디렉토리에 서비스 로그 저장 (Git 무시)
- 주요 지표: gRPC 응답(<100ms), Redis 블랙리스트 latency, 이메일 발송 성공률
- 이메일·GeoIP·proto 빌드 관련 트러블슈팅 명령 제공

## 🧰 Troubleshooting
| 상황 | 대응 |
| --- | --- |
| Redis AOF 비대 | `redis-cli BGREWRITEAOF`로 파일 재작성 |
| GeoIP DB 구버전 | `src/main/resources/GeoLite2-Country.mmdb` 교체 |
| proto regenerate 필요 | `./gradlew clean generateProto` |
| SMTP 오류 | Gmail 2FA + App Password 재발급 후 `application-local.yml` 갱신 |

## 📄 License
MIT License
