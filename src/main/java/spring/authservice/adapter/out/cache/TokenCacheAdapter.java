package spring.authservice.adapter.out.cache;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import spring.authservice.application.port.out.TokenCachePort;

import java.util.concurrent.TimeUnit;

/**
 * 토큰 캐시 어댑터 (Redis 기반)
 * - Refresh Token 블랙리스트 관리
 */
@Component
@RequiredArgsConstructor
public class TokenCacheAdapter implements TokenCachePort {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String BLACKLIST_PREFIX = "blacklist:refresh:";
    private static final long BLACKLIST_TTL_DAYS = 14; // Refresh Token 만료 기간과 동일

    @Override
    public void addToBlacklist(String refreshToken) {
        String key = BLACKLIST_PREFIX + refreshToken;
        redisTemplate.opsForValue().set(key, "blacklisted", BLACKLIST_TTL_DAYS, TimeUnit.DAYS);
    }

    @Override
    public boolean isBlacklisted(String refreshToken) {
        String key = BLACKLIST_PREFIX + refreshToken;
        String value = redisTemplate.opsForValue().get(key);
        return "blacklisted".equals(value);
    }
}
