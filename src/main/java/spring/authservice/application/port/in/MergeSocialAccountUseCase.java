package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 소셜 계정 통합 Use Case
 * - 기존 이메일 계정에 소셜 로그인 연동
 */
public interface MergeSocialAccountUseCase {

    /**
     * 소셜 계정 통합
     * - 기존 이메일 계정의 비밀번호 확인
     * - 소셜 토큰 검증
     * - authProvider 업데이트 및 socialId 저장
     *
     * @param request 통합 요청 (email, password, provider, accessToken)
     * @param httpRequest HTTP 요청 (세션 생성용)
     * @return 통합 결과 (자체 JWT Access Token 포함)
     */
    ResponseEntity<UserDto.SocialMergeResponse> mergeSocialAccount(
            UserDto.SocialMergeRequest request,
            HttpServletRequest httpRequest
    );
}
