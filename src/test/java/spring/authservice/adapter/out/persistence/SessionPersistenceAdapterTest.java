package spring.authservice.adapter.out.persistence;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.domain.model.RefreshTokenSession;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * SessionPersistenceAdapter 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SessionPersistenceAdapter 단위 테스트")
class SessionPersistenceAdapterTest {

    @Mock
    private RefreshTokenSessionRepository sessionRepository;

    @InjectMocks
    private SessionPersistenceAdapter sessionPersistenceAdapter;

    private RefreshTokenSession mockSession;

    @BeforeEach
    void setUp() {
        mockSession = RefreshTokenSession.builder()
                .sessionId(UUID.randomUUID())
                .userId(1L)
                .refreshTokenHash("hash123")
                .encryptedToken("encrypted")
                .deviceName("iPhone")
                .ipAddress("127.0.0.1")
                .country("KR")
                .createdAt(LocalDateTime.now())
                .lastUsedAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("세션 저장 성공")
    void save_Success() {
        // Given
        when(sessionRepository.save(any(RefreshTokenSession.class))).thenReturn(mockSession);

        // When
        RefreshTokenSession saved = sessionPersistenceAdapter.save(mockSession);

        // Then
        assertThat(saved).isNotNull();
        assertThat(saved.getUserId()).isEqualTo(1L);
        verify(sessionRepository, times(1)).save(mockSession);
    }

    @Test
    @DisplayName("사용자 ID로 세션 조회")
    void findByUserId_Success() {
        // Given
        when(sessionRepository.findByUserId(1L)).thenReturn(List.of(mockSession));

        // When
        List<RefreshTokenSession> sessions = sessionPersistenceAdapter.findByUserId(1L);

        // Then
        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).getUserId()).isEqualTo(1L);
        verify(sessionRepository, times(1)).findByUserId(1L);
    }

    @Test
    @DisplayName("토큰 해시로 세션 조회 성공")
    void findByRefreshTokenHash_Success() {
        // Given
        when(sessionRepository.findByRefreshTokenHash(anyString()))
                .thenReturn(Optional.of(mockSession));

        // When
        Optional<RefreshTokenSession> found = sessionPersistenceAdapter
                .findByRefreshTokenHash("hash123");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getRefreshTokenHash()).isEqualTo("hash123");
        verify(sessionRepository, times(1)).findByRefreshTokenHash("hash123");
    }

    @Test
    @DisplayName("세션 ID로 삭제")
    void deleteById_Success() {
        // Given
        UUID sessionId = UUID.randomUUID();

        // When
        sessionPersistenceAdapter.deleteById(sessionId);

        // Then
        verify(sessionRepository, times(1)).deleteById(sessionId);
    }

    @Test
    @DisplayName("사용자 ID로 모든 세션 삭제")
    void deleteByUserId_Success() {
        // Given
        Long userId = 1L;

        // When
        sessionPersistenceAdapter.deleteByUserId(userId);

        // Then
        verify(sessionRepository, times(1)).deleteByUserId(userId);
    }

    @Test
    @DisplayName("만료된 세션 삭제")
    void deleteByCreatedAtBefore_Success() {
        // Given
        LocalDateTime expiryDate = LocalDateTime.now().minusDays(14);

        // When
        sessionPersistenceAdapter.deleteByCreatedAtBefore(expiryDate);

        // Then
        verify(sessionRepository, times(1)).deleteByCreatedAtBefore(expiryDate);
    }

    @Test
    @DisplayName("세션 마지막 사용 시각 업데이트")
    void updateLastUsedAt_Success() {
        // Given
        String tokenHash = "hash123";
        LocalDateTime now = LocalDateTime.now();

        // When
        sessionPersistenceAdapter.updateLastUsedAt(tokenHash, now);

        // Then
        verify(sessionRepository, times(1)).updateLastUsedAt(tokenHash, now);
    }
}
