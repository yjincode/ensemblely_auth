# Auth Service

[![CI](https://github.com/hapiService/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/hapiService/auth-service/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/hapiService/auth-service/branch/main/graph/badge.svg)](https://codecov.io/gh/hapiService/auth-service)

앙상블리 프로젝트의 사용자 인증 및 회원 관리 서비스입니다.

## 🚀 주요 기능

### 인증 & 회원가입
- ✅ 이메일 기반 회원가입
- ✅ 로그인 및 JWT 토큰 발급
- ✅ 아이디 중복 체크
- ✅ 비밀번호 재설정

### 이메일 인증
- ✅ 6자리 인증 코드 발송
- ✅ 원클릭 이메일 인증 링크
- ✅ 5분 TTL 자동 만료
- ✅ Rate Limiting (1분 1회, 하루 10회)
- ✅ Redis 기반 코드 저장

### gRPC 서비스
- ✅ 사용자 정보 조회 (닉네임, 프로필 이미지)
- ✅ 사용자 워크스페이스 제한 조회
- ✅ 일괄 조회 지원

## 🛠 기술 스택

- **Java 21** + **Spring Boot 3.5.6**
- **PostgreSQL** - 사용자 데이터 저장
- **Redis** - 이메일 인증 코드 캐싱
- **gRPC** - 마이크로서비스 간 통신
- **JWT** - 토큰 기반 인증
- **Thymeleaf** - 이메일 템플릿
- **JaCoCo** - 코드 커버리지

## 📦 프로젝트 구조

```
src/main/java/spring/authservice/
├── config/          # 설정 (Security, Redis, JWT)
├── domain/          # Entity & DTO
├── grpc/            # gRPC 서비스 구현
├── service/         # 비즈니스 로직
├── util/            # 유틸리티 (JWT, Password)
└── web/             # REST API 컨트롤러

src/main/proto/      # gRPC 프로토콜 정의
src/main/resources/
├── templates/       # 이메일 템플릿
└── application.yml  # 설정 파일
```

## 🔧 환경 설정

### 1. 로컬 설정 파일 생성

`src/main/resources/application-local.yml` 파일을 생성하세요:

```yaml
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
  issuer: your-issuer
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

# Redis
docker run -d \
  --name auth-redis \
  -p 6379:6379 \
  redis:7
```

### 3. Gmail 앱 비밀번호 발급

1. Google 계정 > 보안 > 2단계 인증 활성화
2. 앱 비밀번호 생성
3. `application-local.yml`에 설정

## 🚀 실행 방법

```bash
# 빌드
./gradlew build

# 테스트
./gradlew test

# 실행
./gradlew bootRun

# gRPC 코드 생성
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

### gRPC (포트 9090)
```protobuf
rpc GetUserNickname(UserIdRequest) returns (UserNicknameResponse);
rpc GetUserNicknames(UserIdsRequest) returns (UserNicknamesResponse);
rpc GetUserMaxWorkspaces(UserIdRequest) returns (UserMaxWorkspacesResponse);
rpc GetUserDisplayInfo(UserIdRequest) returns (UserDisplayInfoResponse);
```

## 🔐 보안

- ✅ BCrypt 비밀번호 암호화
- ✅ JWT 토큰 기반 인증
- ✅ CSRF 비활성화 (Stateless)
- ✅ 환경변수 기반 민감정보 관리
- ✅ 이메일 발송 Rate Limiting

## 📝 개발 가이드

### User 엔티티 필드
- `userId`: 로그인 아이디
- `email`: 이메일 (인증 필수)
- `nickname`: 닉네임
- `password`: BCrypt 암호화된 비밀번호
- `profileImageUrl`: 프로필 이미지 URL
- `authProvider`: 인증 제공자 (EMAIL, GOOGLE, KAKAO 등)
- `accountVerified`: 이메일 인증 여부
- `maxWorkspaces`: 생성 가능한 워크스페이스 수 (기본 2개)

### 이메일 템플릿 커스터마이징
`src/main/resources/templates/` 디렉토리의 HTML 파일을 수정하세요:
- `email-verification.html` - 이메일 인증
- `password-reset-email.html` - 비밀번호 재설정

## 🤝 기여

1. Feature 브랜치 생성
2. 테스트 작성 (커버리지 80% 이상 유지)
3. Pull Request 생성

## 📄 라이선스

MIT License

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
