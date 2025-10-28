package spring.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import spring.authservice.domain.AuditEventType;
import spring.authservice.domain.SecurityAuditLog;
import spring.authservice.domain.SecurityAuditLogRepository;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 보안 감사 로그 서비스
 * - 모든 메서드는 비동기로 실행되어 메인 로직에 영향 없음
 * - 별도 트랜잭션으로 실행 (REQUIRES_NEW)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private final SecurityAuditLogRepository auditRepository;

    /**
     * 감사 로그 저장 (비동기)
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(SecurityAuditLog auditLog) {
        try {
            auditRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to save audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 세션 생성 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSessionCreated(Long userId, UUID sessionId, String deviceName, String ipAddress, String country) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.SESSION_CREATED)
                    .userId(userId)
                    .sessionId(sessionId)
                    .deviceName(deviceName)
                    .ipAddress(ipAddress)
                    .country(country)
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: SESSION_CREATED for user {}", userId);
        } catch (Exception e) {
            log.error("Failed to save SESSION_CREATED audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 세션 무효화 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSessionRevoked(UUID sessionId, Long userId, String deviceName, String reason) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.SESSION_REVOKED)
                    .userId(userId)
                    .sessionId(sessionId)
                    .deviceName(deviceName)
                    .reason(reason)
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: SESSION_REVOKED for session {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to save SESSION_REVOKED audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 모든 세션 무효화 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logAllSessionsRevoked(Long userId, int sessionCount, String reason) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.ALL_SESSIONS_REVOKED)
                    .userId(userId)
                    .reason(reason)
                    .details(String.format("{\"sessionCount\": %d}", sessionCount))
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: ALL_SESSIONS_REVOKED for user {}, count={}", userId, sessionCount);
        } catch (Exception e) {
            log.error("Failed to save ALL_SESSIONS_REVOKED audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 토큰으로 세션 무효화 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSessionRevokedByToken(UUID sessionId, Long userId, String deviceName, String reason) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.SESSION_REVOKED_BY_TOKEN)
                    .userId(userId)
                    .sessionId(sessionId)
                    .deviceName(deviceName)
                    .reason(reason)
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: SESSION_REVOKED_BY_TOKEN for session {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to save SESSION_REVOKED_BY_TOKEN audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 블랙리스트 토큰 시도 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logBlacklistedTokenAttempt(String ipAddress, String requestUri) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.BLACKLISTED_TOKEN_ATTEMPT)
                    .ipAddress(ipAddress)
                    .requestUri(requestUri)
                    .reason("SECURITY_THREAT")
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: BLACKLISTED_TOKEN_ATTEMPT from IP {}", ipAddress);
        } catch (Exception e) {
            log.error("Failed to save BLACKLISTED_TOKEN_ATTEMPT audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 토큰 갱신 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTokenRefreshed(Long userId, String ipAddress) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.TOKEN_REFRESHED)
                    .userId(userId)
                    .ipAddress(ipAddress)
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: TOKEN_REFRESHED for user {}", userId);
        } catch (Exception e) {
            log.error("Failed to save TOKEN_REFRESHED audit log: {}", e.getMessage(), e);
        }
    }

    /**
     * 토큰 검증 실패 로그
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTokenValidationFailed(String ipAddress, String reason, String requestUri) {
        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(AuditEventType.TOKEN_VALIDATION_FAILED)
                    .ipAddress(ipAddress)
                    .reason(reason)
                    .requestUri(requestUri)
                    .build();

            auditRepository.save(auditLog);
            log.debug("Audit log saved: TOKEN_VALIDATION_FAILED from IP {}", ipAddress);
        } catch (Exception e) {
            log.error("Failed to save TOKEN_VALIDATION_FAILED audit log: {}", e.getMessage(), e);
        }
    }
}
