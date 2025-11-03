package spring.authservice.adapter.out.notification;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring.authservice.application.port.out.EmailPort;
import spring.authservice.application.service.EmailService;

/**
 * 이메일 발송 어댑터
 * - EmailService를 통해 이메일 발송 및 인증 기능 제공
 */
@Component
@RequiredArgsConstructor
public class EmailAdapter implements EmailPort {

    private final EmailService emailService;

    @Override
    public boolean sendVerificationEmail(String email) {
        return emailService.sendVerificationEmail(email);
    }

    @Override
    public boolean verifyEmailCode(String email, String verificationCode) {
        return emailService.verifyEmailCode(email, verificationCode);
    }

    @Override
    public String verifyEmailByTokenAndGetEmail(String token) {
        return emailService.verifyEmailByTokenAndGetEmail(token);
    }

    @Override
    public void deleteVerificationCode(String email) {
        emailService.deleteVerificationCode(email);
    }

    @Override
    public boolean sendPasswordResetCode(String email) {
        return emailService.sendPasswordResetCode(email);
    }

    @Override
    public boolean verifyPasswordResetCode(String email, String verificationCode) {
        return emailService.verifyPasswordResetCode(email, verificationCode);
    }

    @Override
    public boolean isPasswordResetVerified(String email) {
        return emailService.isPasswordResetVerified(email);
    }

    @Override
    public void deletePasswordResetVerification(String email) {
        emailService.deletePasswordResetVerification(email);
    }
}
