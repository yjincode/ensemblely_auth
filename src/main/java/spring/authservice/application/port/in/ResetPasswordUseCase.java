package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 비밀번호 재설정 Use Case
 */
public interface ResetPasswordUseCase {

    /**
     * 비밀번호 재설정 코드 발송
     */
    ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(
            UserDto.SendPasswordResetRequest request
    );

    /**
     * 비밀번호 재설정 코드 검증
     */
    ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(
            UserDto.VerifyPasswordResetCodeRequest request
    );

    /**
     * 비밀번호 변경
     */
    ResponseEntity<UserDto.ChangePasswordResponse> changePassword(
            UserDto.ChangePasswordRequest request,
            String refreshToken
    );
}
