package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 사용자 인증 Use Case
 */
public interface AuthenticateUserUseCase {

    /**
     * 로그인 (이메일 + 비밀번호)
     */
    ResponseEntity<UserDto.LoginResponse> authenticateUser(
            UserDto.LoginRequest request,
            HttpServletRequest httpRequest
    );
}
