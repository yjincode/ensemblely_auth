package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 소셜 로그인 Use Case
 */
public interface SocialLoginUseCase {

    /**
     * 소셜 로그인 (네이버, 카카오, 구글)
     * - 프론트엔드에서 받은 OAuth Access Token 검증
     * - 사용자 정보 조회 및 회원가입/로그인 처리
     * - 자체 JWT 토큰 발급
     *
     * @param request 소셜 로그인 요청 (provider, accessToken)
     * @param httpRequest HTTP 요청 (세션 생성용)
     * @return 로그인 결과 (자체 JWT Access Token 포함)
     */
    ResponseEntity<UserDto.SocialLoginResponse> socialLogin(
            UserDto.SocialLoginRequest request,
            HttpServletRequest httpRequest
    );
}
