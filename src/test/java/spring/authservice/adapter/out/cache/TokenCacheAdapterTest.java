package spring.authservice.adapter.out.cache;

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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * TokenCacheAdapter 테스트
 * - Redis 기반 블랙리스트 기능 검증
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TokenCacheAdapter 단위 테스트")
class TokenCacheAdapterTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private TokenCacheAdapter tokenCacheAdapter;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    @DisplayName("블랙리스트에 토큰 추가 성공")
    void addToBlacklist_Success() {
        // Given
        String refreshToken = "test-refresh-token";
        String expectedKey = "blacklist:refresh:" + refreshToken;

        // When
        tokenCacheAdapter.addToBlacklist(refreshToken);

        // Then
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOperations, times(1))
                .set(expectedKey, "blacklisted", 14L, TimeUnit.DAYS);
    }

    @Test
    @DisplayName("블랙리스트 확인 - 등록된 토큰")
    void isBlacklisted_True() {
        // Given
        String refreshToken = "blacklisted-token";
        String expectedKey = "blacklist:refresh:" + refreshToken;
        when(valueOperations.get(expectedKey)).thenReturn("blacklisted");

        // When
        boolean result = tokenCacheAdapter.isBlacklisted(refreshToken);

        // Then
        assertThat(result).isTrue();
        verify(valueOperations, times(1)).get(expectedKey);
    }

    @Test
    @DisplayName("블랙리스트 확인 - 등록되지 않은 토큰")
    void isBlacklisted_False() {
        // Given
        String refreshToken = "valid-token";
        String expectedKey = "blacklist:refresh:" + refreshToken;
        when(valueOperations.get(expectedKey)).thenReturn(null);

        // When
        boolean result = tokenCacheAdapter.isBlacklisted(refreshToken);

        // Then
        assertThat(result).isFalse();
        verify(valueOperations, times(1)).get(expectedKey);
    }
}
