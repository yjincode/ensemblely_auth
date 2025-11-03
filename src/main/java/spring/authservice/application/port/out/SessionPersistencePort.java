package spring.authservice.application.port.out;

import spring.authservice.domain.model.RefreshTokenSession;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * RefreshTokenSession 영속성 Port (Outbound)
 */
public interface SessionPersistencePort {

    /**
     * 세션 저장
     */
    RefreshTokenSession save(RefreshTokenSession session);

    /**
     * 사용자의 모든 세션 조회
     */
    List<RefreshTokenSession> findByUserId(Long userId);

    /**
     * 토큰 해시로 세션 조회
     */
    Optional<RefreshTokenSession> findByRefreshTokenHash(String refreshTokenHash);

    /**
     * 세션 ID로 삭제
     */
    void deleteById(UUID sessionId);

    /**
     * 사용자의 모든 세션 삭제
     */
    void deleteByUserId(Long userId);

    /**
     * 만료된 세션 삭제 (특정 날짜 이전)
     */
    void deleteByCreatedAtBefore(LocalDateTime expiryDate);

    /**
     * 마지막 사용 시각 업데이트
     */
    void updateLastUsedAt(String tokenHash, LocalDateTime now);
}
