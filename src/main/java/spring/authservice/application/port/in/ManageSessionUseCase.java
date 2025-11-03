package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import spring.authservice.domain.vo.UserDto;

import java.util.UUID;

/**
 * 세션 관리 Use Case
 */
public interface ManageSessionUseCase {

    /**
     * 사용자의 모든 세션 조회
     */
    ResponseEntity<UserDto.GetSessionsResponse> getSessions(Long userId);

    /**
     * 특정 세션 삭제
     */
    ResponseEntity<UserDto.DeleteSessionResponse> deleteSession(Long userId, UUID sessionId);

    /**
     * 모든 세션 삭제 (전체 로그아웃)
     */
    ResponseEntity<UserDto.DeleteAllSessionsResponse> deleteAllSessions(Long userId);
}
