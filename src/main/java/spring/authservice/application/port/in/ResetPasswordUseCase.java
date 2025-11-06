package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

public interface ResetPasswordUseCase {

    ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(
            UserDto.SendPasswordResetRequest request
    );

    ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(
            UserDto.VerifyPasswordResetCodeRequest request
    );

    ResponseEntity<UserDto.ResetPasswordResponse> resetPassword(
            UserDto.ResetPasswordRequest request
    );
}
