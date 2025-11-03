package spring.authservice.application.port.in;

import spring.authservice.domain.model.User;

/**
 * 사용자 정보 조회 Use Case (gRPC용)
 */
public interface QueryUserInfoUseCase {

    /**
     * Refresh Token에서 사용자 ID 추출
     */
    Long getUserIdFromRefreshToken(String refreshToken);

    /**
     * 사용자 ID로 사용자 정보 조회
     */
    User getUserById(Long userId);
}
