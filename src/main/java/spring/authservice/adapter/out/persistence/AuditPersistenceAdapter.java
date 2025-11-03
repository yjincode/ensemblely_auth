package spring.authservice.adapter.out.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring.authservice.application.port.out.AuditPersistencePort;
import spring.authservice.domain.model.AuditEventType;
import spring.authservice.domain.model.SecurityAuditLog;

import java.time.LocalDateTime;
import java.util.List;

/**
 * SecurityAuditLog 영속성 어댑터
 * - SecurityAuditLogRepository를 통해 감사 로그 엔티티를 관리
 */
@Component
@RequiredArgsConstructor
public class AuditPersistenceAdapter implements AuditPersistencePort {

    private final SecurityAuditLogRepository securityAuditLogRepository;

    @Override
    public SecurityAuditLog save(SecurityAuditLog auditLog) {
        return securityAuditLogRepository.save(auditLog);
    }

    @Override
    public List<SecurityAuditLog> findByUserIdOrderByTimestampDesc(Long userId) {
        return securityAuditLogRepository.findByUserIdOrderByTimestampDesc(userId);
    }

    @Override
    public List<SecurityAuditLog> findByUserIdAndEventTypeOrderByTimestampDesc(Long userId, AuditEventType eventType) {
        return securityAuditLogRepository.findByUserIdAndEventTypeOrderByTimestampDesc(userId, eventType);
    }

    @Override
    public List<SecurityAuditLog> findByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate) {
        return securityAuditLogRepository.findByTimestampBetween(startDate, endDate);
    }

    @Override
    public long countByEventType(AuditEventType eventType) {
        return securityAuditLogRepository.countByEventType(eventType);
    }

    @Override
    public List<SecurityAuditLog> findRecentLoginsByUserId(Long userId) {
        return securityAuditLogRepository.findRecentLoginsByUserId(userId);
    }
}
