package spring.authservice.application.port.in;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

/**
 * 소셜 계정 통합 Use Case
 * - 기존 이메일 계정에 소셜 로그인 연동
 * - 신규 소셜 계정 생성
 */
public interface MergeSocialAccountUseCase {

    /**
     * 소셜 계정 통합 또는 신규 계정 생성
     * - mergeWithExisting이 true: 기존 이메일 계정에 소셜 계정 통합
     * - mergeWithExisting이 false: 신규 소셜 계정 생성
     *
     * @param request 통합/생성 요청 (email, password, mergeToken, mergeWithExisting)
     * @param httpRequest HTTP 요청 (세션 생성용)
     * @return 결과 (자체 JWT Access Token 포함)
     */
    ResponseEntity<UserDto.SocialMergeResponse> mergeSocialAccount(
            UserDto.SocialMergeRequest request,
            HttpServletRequest httpRequest
    );
}
