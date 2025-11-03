package spring.authservice.application.port.out;

import spring.authservice.domain.model.AuditEventType;
import spring.authservice.domain.model.SecurityAuditLog;

import java.time.LocalDateTime;
import java.util.List;

/**
 * SecurityAuditLog 영속성 Port (Outbound)
 */
public interface AuditPersistencePort {

    /**
     * 감사 로그 저장
     */
    SecurityAuditLog save(SecurityAuditLog auditLog);

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
    List<SecurityAuditLog> findByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * 특정 이벤트 유형의 로그 개수
     */
    long countByEventType(AuditEventType eventType);

    /**
     * 특정 사용자의 최근 로그인 이력
     */
    List<SecurityAuditLog> findRecentLoginsByUserId(Long userId);
}
