package spring.authservice.application.port.out;

/**
 * 토큰 캐시 Port (Outbound)
 * - Redis, Memcached 등 다양한 구현체 가능
 */
public interface TokenCachePort {

    /**
     * Refresh Token을 블랙리스트에 추가
     */
    void addToBlacklist(String refreshToken);

    /**
     * Refresh Token이 블랙리스트에 있는지 확인
     */
    boolean isBlacklisted(String refreshToken);
}
