package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 토큰 관리 Use Case (재발급, 로그아웃)
 */
public interface ManageTokenUseCase {

    ResponseEntity<UserDto.RefreshTokenResponse> refreshAccessToken(String refreshToken);

    ResponseEntity<UserDto.LogoutResponse> logout(String refreshToken);
}
