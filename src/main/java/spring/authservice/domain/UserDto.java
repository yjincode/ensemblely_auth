package spring.authservice.domain;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 사용자 관련 DTO 통합 클래스
 */
public class UserDto {

    // === 회원가입 관련 ===

    @Getter
    @Builder
    public static class LocalJoinRequest {
        private String userId;
        private String email;
        private String username;
        private String nickname;
        private String password;
        private AuthProviderEnum authProvider;

        public User toUser(BCryptPasswordEncoder bCryptPasswordEncoder) {
            return User.builder()
                    .userId(userId)
                    .email(email)
                    .nickname(nickname)
                    .username(username)
                    .password(bCryptPasswordEncoder.encode(password.toLowerCase()))  // 대소문자 구분 안함
                    .authProvider(AuthProviderEnum.EMAIL)
                    .accountVerified(false)     // 초기 가입시 미인증 상태
                    .build();
        }
    }

    @Getter
    @Builder
    public static class LocalJoinResponse {
        private boolean success;
        private String message;
        private String token;       // JWT 토큰 (회원가입 성공시 자동 로그인)
    }

    // === 로그인 관련 ===

    @Getter
    @Builder
    public static class LoginRequest {
        private String userId;      // 로그인 아이디
        private String password;    // 비밀번호
    }

    @Getter
    @Builder
    public static class LoginResponse {
        private boolean success;
        private String message;
        private String token;       // JWT 토큰 (로그인 성공시에만)
    }

    // === 아이디 중복 체크 ===

    @Getter
    @Builder
    public static class IsUserIdAvailableResponse {
        private boolean success;
        private String message;
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

    // === 비밀번호 재설정 관련 ===

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
    public static class ChangePasswordRequest {
        private String email;
        private String newPassword;
    }

    @Getter
    @Builder
    public static class ChangePasswordResponse {
        private boolean success;
        private String message;
    }

    // === 토큰 재발급 관련 ===

    @Getter
    @Builder
    public static class RefreshTokenResponse {
        private boolean success;
        private String message;
        private String token;       // 새로 발급된 Access Token
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
}
