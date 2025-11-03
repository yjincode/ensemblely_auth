package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import spring.authservice.domain.vo.UserDto;

/**
 * 회원가입 및 이메일 인증 Use Case
 */
public interface RegisterUserUseCase {

    /**
     * 로컬 회원가입 (이메일 + 비밀번호)
     */
    ResponseEntity<UserDto.LocalJoinResponse> registerUser(
            UserDto.LocalJoinRequest request,
            HttpServletRequest httpRequest
    );

    /**
     * 이메일 인증 코드 발송
     */
    ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(
            UserDto.SendEmailVerificationRequest request
    );

    /**
     * 이메일 인증 코드 검증
     */
    ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(
            UserDto.VerifyEmailCodeRequest request
    );

    /**
     * 토큰 기반 이메일 인증 (HTML 응답용)
     */
    String verifyEmailByTokenForHtml(String token, Model model);
}
