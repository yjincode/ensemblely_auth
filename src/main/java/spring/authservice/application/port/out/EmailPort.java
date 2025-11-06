package spring.authservice.application.port.out;

import spring.authservice.application.service.EmailService.RateLimitResult;

/**
 * 이메일 발송 Port (Outbound)
 * - SMTP, AWS SES, SendGrid 등 다양한 구현체 가능
 */
public interface EmailPort {

    /**
     * 이메일 인증 코드 발송
     * @return Rate Limit 결과 (ALLOWED, MINUTE_LIMIT, DAILY_LIMIT)
     */
    RateLimitResult sendVerificationEmail(String email);

    /**
     * 이메일 인증 코드 검증
     */
    boolean verifyEmailCode(String email, String verificationCode);

    /**
     * 토큰 기반 이메일 인증 후 이메일 주소 반환
     * @return 인증된 이메일 주소 (실패 시 null)
     */
    String verifyEmailByTokenAndGetEmail(String token);

    /**
     * 비밀번호 재설정 코드 발송
     * @return Rate Limit 결과 (ALLOWED, MINUTE_LIMIT, DAILY_LIMIT)
     */
    RateLimitResult sendPasswordResetCode(String email);

    /**
     * 비밀번호 재설정 코드 검증
     */
    boolean verifyPasswordResetCode(String email, String verificationCode);

    /**
     * 비밀번호 재설정이 인증되었는지 확인
     */
    boolean isPasswordResetVerified(String email);

    /**
     * 비밀번호 재설정 인증 정보 삭제
     */
    void deletePasswordResetVerification(String email);
}
