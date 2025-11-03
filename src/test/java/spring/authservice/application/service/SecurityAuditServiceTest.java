package spring.authservice.application.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.adapter.out.persistence.SecurityAuditLogRepository;
import spring.authservice.domain.model.AuditEventType;
import spring.authservice.domain.model.SecurityAuditLog;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * SecurityAuditService 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SecurityAuditService 단위 테스트")
class SecurityAuditServiceTest {

    @Mock
    private SecurityAuditLogRepository auditRepository;

    @InjectMocks
    private SecurityAuditService auditService;

    @Test
    @DisplayName("감사 로그 저장 성공")
    void log_Success() {
        // Given
        SecurityAuditLog log = SecurityAuditLog.builder()
                .userId(1L)
                .eventType(AuditEventType.SESSION_CREATED)
                .build();

        when(auditRepository.save(any(SecurityAuditLog.class))).thenReturn(log);

        // When
        auditService.log(log);

        // Then
        verify(auditRepository, times(1)).save(log);
    }

    @Test
    @DisplayName("세션 생성 로그 성공")
    void logSessionCreated_Success() {
        // Given
        Long userId = 1L;
        UUID sessionId = UUID.randomUUID();
        String deviceName = "iPhone";
        String ipAddress = "127.0.0.1";
        String country = "KR";

        // When
        auditService.logSessionCreated(userId, sessionId, deviceName, ipAddress, country);

        // Then
        verify(auditRepository, times(1)).save(any(SecurityAuditLog.class));
    }

    @Test
    @DisplayName("세션 무효화 로그 성공")
    void logSessionRevoked_Success() {
        // Given
        UUID sessionId = UUID.randomUUID();
        Long userId = 1L;
        String deviceName = "iPhone";
        String reason = "USER_LOGOUT";

        // When
        auditService.logSessionRevoked(sessionId, userId, deviceName, reason);

        // Then
        verify(auditRepository, times(1)).save(any(SecurityAuditLog.class));
    }

    @Test
    @DisplayName("전체 세션 무효화 로그 성공")
    void logAllSessionsRevoked_Success() {
        // Given
        Long userId = 1L;
        int sessionCount = 3;
        String reason = "PASSWORD_CHANGE";

        // When
        auditService.logAllSessionsRevoked(userId, sessionCount, reason);

        // Then
        verify(auditRepository, times(1)).save(any(SecurityAuditLog.class));
    }
}
