package spring.authservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Refresh Token 블랙리스트 관리 서비스
 * 로그아웃/비밀번호 변경 시 토큰을 블랙리스트에 추가하여 무효화
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenBlacklistService {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String BLACKLIST_PREFIX = "blacklist:refresh:";
    private static final long BLACKLIST_TTL_DAYS = 14; // Refresh Token 만료 기간과 동일

    /**
     * Refresh Token을 블랙리스트에 추가
     * @param token Refresh Token
     */
    public void addToBlacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        // TTL을 Refresh Token 만료 기간과 동일하게 설정 (메모리 절약)
        redisTemplate.opsForValue().set(key, "blacklisted", BLACKLIST_TTL_DAYS, TimeUnit.DAYS);
    }

    /**
     * Refresh Token이 블랙리스트에 있는지 확인
     * @param token Refresh Token
     * @return 블랙리스트에 있으면 true
     */
    public boolean isBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        String value = redisTemplate.opsForValue().get(key);
        return "blacklisted".equals(value);
    }

    /**
     * 특정 사용자의 모든 Refresh Token을 블랙리스트에 추가
     * (비밀번호 변경 시 사용 - 모든 기기에서 로그아웃)
     * @param userId 사용자 ID
     * @param currentToken 현재 사용 중인 토큰 (선택적)
     */
    public void blacklistAllUserTokens(Long userId, String currentToken) {
        if (currentToken != null) {
            addToBlacklist(currentToken);
        }

        // Note: 현재는 단일 토큰만 블랙리스트에 추가
        // 추가 개선: 사용자별 발급된 모든 토큰을 추적하려면 별도 저장소 필요
    }
}
