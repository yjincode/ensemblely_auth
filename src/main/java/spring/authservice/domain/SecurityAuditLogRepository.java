package spring.authservice.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    /**
     * 특정 사용자의 모든 감사 로그 조회
     */
    List<SecurityAuditLog> findByUserIdOrderByTimestampDesc(Long userId);

    /**
     * 특정 사용자의 특정 이벤트 조회
     */
    List<SecurityAuditLog> findByUserIdAndEventTypeOrderByTimestampDesc(Long userId, AuditEventType eventType);

    /**
     * 특정 기간의 모든 감사 로그 조회
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    List<SecurityAuditLog> findByTimestampBetween(@Param("startDate") LocalDateTime startDate,
                                                    @Param("endDate") LocalDateTime endDate);

    /**
     * 특정 이벤트 유형의 로그 개수
     */
    long countByEventType(AuditEventType eventType);

    /**
     * 특정 사용자의 최근 로그인 이력
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.userId = :userId AND a.eventType = 'SESSION_CREATED' ORDER BY a.timestamp DESC")
    List<SecurityAuditLog> findRecentLoginsByUserId(@Param("userId") Long userId);
}
