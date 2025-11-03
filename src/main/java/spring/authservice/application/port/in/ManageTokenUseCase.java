package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 토큰 관리 Use Case (재발급, 로그아웃)
 */
public interface ManageTokenUseCase {

    /**
     * Refresh Token으로 새로운 Access Token 발급
     */
    ResponseEntity<UserDto.RefreshTokenResponse> refreshAccessToken(String refreshToken);

    /**
     * 로그아웃 (Refresh Token 블랙리스트 추가)
     */
    ResponseEntity<UserDto.LogoutResponse> logout(String refreshToken);
}
