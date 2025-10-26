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
     *
     * ⚠️ 현재 구조에서는 불필요함
     * 이유: RefreshTokenSessionService.deleteAllUserSessions()로 세션을 삭제하면
     * 세션이 없어서 인증이 자동으로 실패하므로 블랙리스트 추가가 불필요
     *
     * 세션 기반 시스템에서는:
     * - 세션 삭제 = 토큰 무효화 (세션 없으면 인증 실패)
     * - 블랙리스트는 세션이 남아있는 상태에서 토큰만 무효화할 때 사용
     *
     * @deprecated 대신 RefreshTokenSessionService.deleteAllUserSessions() 사용
     * @param userId 사용자 ID
     * @param currentToken 현재 사용 중인 토큰 (선택적)
     */
    @Deprecated
    public void blacklistAllUserTokens(Long userId, String currentToken) {
        // 현재 토큰만 블랙리스트에 추가
        // (나머지는 세션 삭제로 무효화됨)
        if (currentToken != null) {
            addToBlacklist(currentToken);
        }
    }
}
