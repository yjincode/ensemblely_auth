package spring.authservice.adapter.out.persistence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.domain.model.AuditEventType;
import spring.authservice.domain.model.SecurityAuditLog;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * AuditPersistenceAdapter 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditPersistenceAdapter 단위 테스트")
class AuditPersistenceAdapterTest {

    @Mock
    private SecurityAuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditPersistenceAdapter auditPersistenceAdapter;

    @Test
    @DisplayName("감사 로그 저장 성공")
    void save_Success() {
        // Given
        SecurityAuditLog mockLog = SecurityAuditLog.builder()
                .userId(1L)
                .eventType(AuditEventType.SESSION_CREATED)
                .ipAddress("127.0.0.1")
                .timestamp(LocalDateTime.now())
                .build();

        when(auditLogRepository.save(any(SecurityAuditLog.class))).thenReturn(mockLog);

        // When
        SecurityAuditLog saved = auditPersistenceAdapter.save(mockLog);

        // Then
        assertThat(saved).isNotNull();
        assertThat(saved.getEventType()).isEqualTo(AuditEventType.SESSION_CREATED);
        verify(auditLogRepository, times(1)).save(mockLog);
    }

    @Test
    @DisplayName("사용자 ID로 감사 로그 조회")
    void findByUserId_Success() {
        // Given
        Long userId = 1L;
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(userId))
                .thenReturn(List.of());

        // When
        List<SecurityAuditLog> logs = auditPersistenceAdapter
                .findByUserIdOrderByTimestampDesc(userId);

        // Then
        assertThat(logs).isNotNull();
        verify(auditLogRepository, times(1))
                .findByUserIdOrderByTimestampDesc(userId);
    }

    @Test
    @DisplayName("이벤트 타입 카운트 조회")
    void countByEventType_Success() {
        // Given
        AuditEventType eventType = AuditEventType.SESSION_CREATED;
        when(auditLogRepository.countByEventType(eventType)).thenReturn(10L);

        // When
        long count = auditPersistenceAdapter.countByEventType(eventType);

        // Then
        assertThat(count).isEqualTo(10L);
        verify(auditLogRepository, times(1)).countByEventType(eventType);
    }
}
