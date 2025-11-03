package spring.authservice.application.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * RefreshTokenBlacklistService 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenBlacklistService 단위 테스트")
class RefreshTokenBlacklistServiceTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private RefreshTokenBlacklistService blacklistService;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    @DisplayName("블랙리스트에 토큰 추가 성공")
    void addToBlacklist_Success() {
        // Given
        String token = "test-refresh-token";

        // When
        blacklistService.addToBlacklist(token);

        // Then
        verify(valueOperations, times(1))
                .set(eq("blacklist:refresh:" + token),
                     eq("blacklisted"),
                     eq(14L),
                     eq(TimeUnit.DAYS));
    }

    @Test
    @DisplayName("블랙리스트 확인 - 등록된 토큰")
    void isBlacklisted_True() {
        // Given
        String token = "blacklisted-token";
        when(valueOperations.get("blacklist:refresh:" + token))
                .thenReturn("blacklisted");

        // When
        boolean result = blacklistService.isBlacklisted(token);

        // Then
        assertThat(result).isTrue();
        verify(valueOperations, times(1))
                .get("blacklist:refresh:" + token);
    }

    @Test
    @DisplayName("블랙리스트 확인 - 등록되지 않은 토큰")
    void isBlacklisted_False() {
        // Given
        String token = "valid-token";
        when(valueOperations.get(anyString())).thenReturn(null);

        // When
        boolean result = blacklistService.isBlacklisted(token);

        // Then
        assertThat(result).isFalse();
        verify(valueOperations, times(1))
                .get("blacklist:refresh:" + token);
    }
}
