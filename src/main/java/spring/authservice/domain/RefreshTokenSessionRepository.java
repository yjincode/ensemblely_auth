package spring.authservice.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenSessionRepository extends JpaRepository<RefreshTokenSession, UUID> {

    /**
     * 사용자의 모든 세션 조회
     */
    List<RefreshTokenSession> findByUserId(Long userId);

    /**
     * 토큰 해시로 세션 조회
     */
    Optional<RefreshTokenSession> findByRefreshTokenHash(String refreshTokenHash);

    /**
     * 사용자의 모든 세션 삭제
     */
    void deleteByUserId(Long userId);

    /**
     * 특정 날짜 이전에 생성된 세션 삭제 (만료 세션 정리)
     */
    @Modifying
    @Query("DELETE FROM RefreshTokenSession s WHERE s.createdAt < :expiryDate")
    void deleteByCreatedAtBefore(@Param("expiryDate") LocalDateTime expiryDate);

    /**
     * last_used_at 업데이트
     */
    @Modifying
    @Query("UPDATE RefreshTokenSession s SET s.lastUsedAt = :now WHERE s.refreshTokenHash = :tokenHash")
    void updateLastUsedAt(@Param("tokenHash") String tokenHash, @Param("now") LocalDateTime now);

    /**
     * revoked된 세션 조회 (블랙리스트 복구용)
     */
    List<RefreshTokenSession> findByRevokedTrue();
}
