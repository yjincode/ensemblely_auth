package spring.authservice.application.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.adapter.out.persistence.RefreshTokenSessionRepository;
import spring.authservice.domain.model.RefreshTokenSession;
import spring.authservice.util.CryptoUtil;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * RefreshTokenSessionService 테스트
 * - 핵심 세션 관리 기능 검증
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenSessionService 단위 테스트")
class RefreshTokenSessionServiceTest {

    @Mock
    private RefreshTokenSessionRepository sessionRepository;

    @Mock
    private CryptoUtil cryptoUtil;

    @Mock
    private GeoIpService geoIpService;

    @Mock
    private RefreshTokenBlacklistService blacklistService;

    @Mock
    private SecurityAuditService auditService;

    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private RefreshTokenSessionService sessionService;

    @Test
    @DisplayName("세션 생성 성공")
    void createSession_Success() {
        // Given
        Long userId = 1L;
        String refreshToken = "test-refresh-token";
        String tokenHash = "hash123";
        String encryptedToken = "encrypted";

        lenient().when(cryptoUtil.hashRefreshToken(refreshToken)).thenReturn(tokenHash);
        lenient().when(cryptoUtil.encryptToken(refreshToken)).thenReturn(encryptedToken);
        lenient().when(cryptoUtil.encryptIpAddress(anyString())).thenReturn("encrypted-ip");
        lenient().when(geoIpService.getCountryCode(anyString())).thenReturn("KR");
        lenient().when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        lenient().when(httpServletRequest.getHeader(anyString())).thenReturn("Mozilla/5.0");

        RefreshTokenSession mockSession = RefreshTokenSession.builder()
                .sessionId(UUID.randomUUID())
                .userId(userId)
                .refreshTokenHash(tokenHash)
                .build();

        when(sessionRepository.save(any(RefreshTokenSession.class))).thenReturn(mockSession);

        // When
        RefreshTokenSession session = sessionService.createSession(userId, refreshToken, httpServletRequest);

        // Then
        assertThat(session).isNotNull();
        verify(sessionRepository, times(1)).save(any(RefreshTokenSession.class));
        verify(auditService, times(1)).logSessionCreated(anyLong(), any(UUID.class), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("사용자의 모든 세션 조회")
    void getUserSessions_Success() {
        // Given
        Long userId = 1L;
        when(sessionRepository.findByUserId(userId)).thenReturn(List.of());

        // When
        List<RefreshTokenSession> sessions = sessionService.getUserSessions(userId);

        // Then
        assertThat(sessions).isNotNull();
        verify(sessionRepository, times(1)).findByUserId(userId);
    }

    @Test
    @DisplayName("토큰으로 세션 삭제 성공")
    void deleteSessionByToken_Success() {
        // Given
        String refreshToken = "test-token";
        String tokenHash = "hash123";
        UUID sessionId = UUID.randomUUID();

        RefreshTokenSession mockSession = RefreshTokenSession.builder()
                .sessionId(sessionId)
                .userId(1L)
                .refreshTokenHash(tokenHash)
                .encryptedToken("encrypted")
                .deviceName("iPhone")
                .build();

        lenient().when(cryptoUtil.hashRefreshToken(refreshToken)).thenReturn(tokenHash);
        lenient().when(sessionRepository.findByRefreshTokenHash(tokenHash))
                .thenReturn(Optional.of(mockSession));
        lenient().when(cryptoUtil.decryptToken(anyString())).thenReturn(refreshToken);

        // When
        boolean result = sessionService.deleteSessionByToken(refreshToken);

        // Then
        assertThat(result).isTrue();
        verify(blacklistService, times(1)).addToBlacklist(refreshToken);
        verify(sessionRepository, times(1)).delete(mockSession);
    }

    @Test
    @DisplayName("만료된 세션 정리")
    void cleanExpiredSessions_Success() {
        // When
        sessionService.cleanExpiredSessions();

        // Then
        verify(sessionRepository, times(1))
                .deleteByCreatedAtBefore(any(LocalDateTime.class));
    }
}
