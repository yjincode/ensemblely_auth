package spring.authservice.domain.vo;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

/**
 * 사용자 관련 DTO 통합 클래스
 */
public class UserDto {

    // === 회원가입 관련 ===

    @Getter
    @Builder
    public static class LocalJoinRequest {
        private String email;
        private String username;
        private String nickname;
        private String password;
        private AuthProviderEnum authProvider;

        public User toUser(BCryptPasswordEncoder bCryptPasswordEncoder) {
            return User.builder()
                    .email(email)
                    .nickname(nickname)
                    .username(username)
                    .password(bCryptPasswordEncoder.encode(password.toLowerCase()))  // 대소문자 구분 안함
                    .authProvider(AuthProviderEnum.EMAIL)
                    .build();
        }
    }

    @Getter
    @Builder
    public static class LocalJoinResponse {
        private boolean success;
        private String message;
        private String accessToken;       // JWT 토큰 (회원가입 성공시 자동 로그인)
    }

    // === 로그인 관련 ===

    @Getter
    @Builder
    public static class LoginRequest {
        private String email;       // 이메일 (로그인 아이디)
        private String password;    // 비밀번호
    }

    @Getter
    @Builder
    public static class LoginResponse {
        private boolean success;
        private String message;
        private String accessToken;       // JWT 토큰 (로그인 성공시에만)
    }

    // === 이메일 인증 관련 ===

    @Getter
    @Builder
    public static class SendEmailVerificationRequest {
        private String email;
    }

    @Getter
    @Builder
    public static class SendEmailVerificationResponse {
        private boolean success;
        private String message;
    }

    @Getter
    @Builder
    public static class VerifyEmailCodeRequest {
        private String email;
        private String verificationCode;
    }

    @Getter
    @Builder
    public static class VerifyEmailCodeResponse {
        private boolean success;
        private String message;
    }

    // === 비밀번호 재설정 관련 (이메일 인증 - Public API) ===

    @Getter
    @Builder
    public static class SendPasswordResetRequest {
        private String email;
    }

    @Getter
    @Builder
    public static class SendPasswordResetResponse {
        private boolean success;
        private String message;
    }

    @Getter
    @Builder
    public static class VerifyPasswordResetCodeRequest {
        private String email;
        private String verificationCode;
    }

    @Getter
    @Builder
    public static class VerifyPasswordResetCodeResponse {
        private boolean success;
        private String message;
    }

    @Getter
    @Builder
    public static class ResetPasswordRequest {
        private String email;
        private String newPassword;
    }

    @Getter
    @Builder
    public static class ResetPasswordResponse {
        private boolean success;
        private String message;
    }

    // === 비밀번호 변경 관련 (로그인 상태 - Authenticated API) ===

    @Getter
    @Builder
    public static class UpdatePasswordRequest {
        private String currentPassword;
        private String newPassword;
    }

    @Getter
    @Builder
    public static class UpdatePasswordResponse {
        private boolean success;
        private String message;
    }

    // === 프로필 이미지 관련 ===

    @Getter
    @Builder
    public static class UploadProfileImageResponse {
        private boolean success;
        private String message;
        private String imageUrl;
    }

    @Getter
    @Builder
    public static class DeleteProfileImageResponse {
        private boolean success;
        private String message;
    }

    // === 토큰 재발급 관련 ===

    @Getter
    @Builder
    public static class RefreshTokenResponse {
        private boolean success;
        private String message;
        private String accessToken;       // 새로 발급된 Access Token
        private long accessTokenExpiresIn;  // Access Token 만료 시간 (초)
    }

    // === 로그아웃 관련 ===

    @Getter
    @Builder
    public static class LogoutResponse {
        private boolean success;
        private String message;
    }

    // === 세션 관리 관련 ===

    @Getter
    @Builder
    public static class SessionInfo {
        private String sessionId;       // UUID
        private String deviceName;      // 기기명 (예: "iPhone", "Windows PC")
        private String country;         // 국가 코드 (예: "KR", "US")
        private String lastUsedAt;      // 마지막 사용 시각 (ISO-8601 형식)
    }

    @Getter
    @Builder
    public static class GetSessionsResponse {
        private boolean success;
        private String message;
        private java.util.List<SessionInfo> sessions;
    }

    @Getter
    @Builder
    public static class DeleteSessionResponse {
        private boolean success;
        private String message;
    }

    @Getter
    @Builder
    public static class DeleteAllSessionsResponse {
        private boolean success;
        private String message;
        private int deletedCount;       // 삭제된 세션 수
    }

    // === 소셜 로그인 관련 ===

    @Getter
    @Builder
    public static class SocialLoginRequest {
        private String provider;        // "naver", "kakao", "google"
        private String code;            // 프론트엔드에서 받은 Authorization Code
        private String state;           // 네이버 전용 CSRF 방지 state (선택)
    }

    @Getter
    @Builder
    public static class SocialLoginResponse {
        private boolean success;
        private String message;
        private String accessToken;     // 자체 JWT Access Token (통합 필요 시 null)
        private boolean isNewUser;      // 신규 가입 여부
        private Boolean mergeRequired;  // 계정 통합 필요 여부 (409일 때만 true)
        private String email;           // 통합 대상 이메일 (409일 때만 포함)
        private String mergeToken;      // 계정 통합용 임시 토큰 (409일 때만 포함)
    }

    @Getter
    @Builder
    public static class SocialMergeRequest {
        private String email;           // 기존 계정 이메일 (통합 시에만 필요)
        private String password;        // 기존 계정 비밀번호 (통합 시에만 필요)
        private String mergeToken;      // Redis에 저장된 임시 검증 토큰
        private boolean mergeWithExisting; // true: 기존 계정 통합, false: 신규 계정 생성
    }

    @Getter
    @Builder
    public static class SocialMergeResponse {
        private boolean success;
        private String message;
        private String accessToken;     // 자체 JWT Access Token
    }

    // === Redis 임시 검증 토큰 ===

    @Getter
    @Builder
    public static class SocialMergeTokenData {
        private String email;           // 소셜 계정 이메일
        private String socialId;        // 소셜 계정 ID
        private String provider;        // "naver", "google" (kakao는 통합 불가)
        private String name;            // 소셜 계정 실명
        private String profileImageUrl; // 소셜 계정 프로필 이미지 (선택)
    }
}
