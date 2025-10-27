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
     *
     * @deprecated 더 이상 사용하지 않음
     *
     * 현재는 RefreshTokenSessionService.deleteAllUserSessions()가
     * 세션 삭제 시 자동으로 모든 토큰을 블랙리스트에 추가함
     *
     * 변경된 흐름:
     * 1. 세션 삭제 요청 → deleteAllUserSessions() 호출
     * 2. 세션에 저장된 암호화된 토큰 복호화
     * 3. 블랙리스트에 추가 (addToBlacklist)
     * 4. 세션 삭제
     *
     */
    @Deprecated
    public void blacklistAllUserTokens(String currentToken) {
        if (currentToken != null) {
            addToBlacklist(currentToken);
        }
    }
}
