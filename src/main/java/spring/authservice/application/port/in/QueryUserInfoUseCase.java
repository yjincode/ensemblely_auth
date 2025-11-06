package spring.authservice.application.port.in;

import spring.authservice.domain.model.User;

/**
 * 사용자 정보 조회 Use Case (gRPC용)
 */
public interface QueryUserInfoUseCase {

    Long getUserIdFromRefreshToken(String refreshToken);

    User getUserById(Long userId);
}
