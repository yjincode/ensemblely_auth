package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import spring.authservice.domain.vo.UserDto;

/**
 * 회원가입 및 이메일 인증 Use Case
 */
public interface RegisterUserUseCase {

    ResponseEntity<UserDto.LocalJoinResponse> registerUser(
            UserDto.LocalJoinRequest request,
            HttpServletRequest httpRequest
    );

    ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(
            UserDto.SendEmailVerificationRequest request
    );

    ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(
            UserDto.VerifyEmailCodeRequest request
    );

    String verifyEmailByTokenForHtml(String token, Model model);
}
