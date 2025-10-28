package spring.authservice.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.authservice.domain.RefreshTokenSession;
import spring.authservice.domain.RefreshTokenSessionRepository;
import spring.authservice.util.CryptoUtil;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Refresh Token 세션 관리 서비스
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenSessionService {

    private final RefreshTokenSessionRepository sessionRepository;
    private final CryptoUtil cryptoUtil;
    private final GeoIpService geoIpService;
    private final RefreshTokenBlacklistService blacklistService;
    private final SecurityAuditService auditService;

    /**
     * 세션 생성 (로그인 시)
     */
    @Transactional
    public RefreshTokenSession createSession(
            Long userId,
            String refreshToken,
            HttpServletRequest request
    ) {
        // 1. Refresh Token 해싱 및 암호화
        String tokenHash = cryptoUtil.hashRefreshToken(refreshToken);
        String encryptedToken = cryptoUtil.encryptToken(refreshToken);

        // 2. 클라이언트 정보 수집
        String ipAddress = getClientIp(request);
        String encryptedIp = cryptoUtil.encryptIpAddress(ipAddress);
        String deviceName = extractDeviceName(request);
        String country = geoIpService.getCountryCode(ipAddress);

        // 3. 세션 생성
        RefreshTokenSession session = RefreshTokenSession.builder()
                .sessionId(UUID.randomUUID())
                .userId(userId)
                .refreshTokenHash(tokenHash)
                .encryptedToken(encryptedToken)
                .deviceName(deviceName)
                .ipAddress(encryptedIp)
                .country(country)
                .createdAt(LocalDateTime.now())
                .lastUsedAt(LocalDateTime.now())
                .build();

        RefreshTokenSession savedSession = sessionRepository.save(session);

        // 감사 로그: 세션 생성 (비동기 DB 저장)
        auditService.logSessionCreated(userId, savedSession.getSessionId(), deviceName, ipAddress, country);

        return savedSession;
    }

    /**
     * 토큰 해시로 세션 조회
     */
    public RefreshTokenSession findByTokenHash(String tokenHash) {
        return sessionRepository.findByRefreshTokenHash(tokenHash).orElse(null);
    }

    /**
     * 마지막 사용 시각 업데이트 (비동기)
     */
    @Async
    @Transactional
    public void updateLastUsedAt(String refreshToken) {
        String tokenHash = cryptoUtil.hashRefreshToken(refreshToken);
        sessionRepository.updateLastUsedAt(tokenHash, LocalDateTime.now());
    }

    /**
     * 사용자의 모든 세션 조회 (UI용)
     */
    public List<RefreshTokenSession> getUserSessions(Long userId) {
        return sessionRepository.findByUserId(userId);
    }

    /**
     * 특정 세션 무효화
     * - Redis: 블랙리스트 추가 (필터 검증용, AOF로 영속성 보장)
     * - DB: 세션 삭제
     * - Audit: 로그 기록 (감사 추적)
     */
    @Transactional
    public void deleteSession(UUID sessionId) {
        // 1. 세션 조회
        RefreshTokenSession session = sessionRepository.findById(sessionId).orElse(null);

        if (session != null) {
            // 2. Redis: 블랙리스트 추가 (필수)
            String refreshToken = cryptoUtil.decryptToken(session.getEncryptedToken());
            blacklistService.addToBlacklist(refreshToken);

            // 3. 감사 로그: 세션 무효화 (비동기 DB 저장, 삭제 전에 호출)
            auditService.logSessionRevoked(sessionId, session.getUserId(), session.getDeviceName(), "USER_LOGOUT");

            // 4. DB: 세션 삭제
            sessionRepository.delete(session);

            log.info("Session revoked and blacklisted: sessionId={}", sessionId);
        }
    }

    /**
     * 사용자의 모든 세션 무효화 (전체 로그아웃)
     * - Redis: 블랙리스트 추가 (필터 검증용, AOF로 영속성 보장)
     * - DB: 세션 삭제
     * - Audit: 로그 기록 (감사 추적)
     */
    @Transactional
    public int deleteAllUserSessions(Long userId) {
        // 1. 사용자의 모든 세션 조회
        List<RefreshTokenSession> sessions = sessionRepository.findByUserId(userId);

        // 2. 각 세션 무효화
        for (RefreshTokenSession session : sessions) {
            // 2-1. Redis: 블랙리스트 추가 (필수)
            String refreshToken = cryptoUtil.decryptToken(session.getEncryptedToken());
            blacklistService.addToBlacklist(refreshToken);
        }

        // 3. 감사 로그: 전체 세션 무효화 (비동기 DB 저장)
        auditService.logAllSessionsRevoked(userId, sessions.size(), "PASSWORD_CHANGE_OR_SECURITY");

        // 4. DB: 모든 세션 삭제
        sessionRepository.deleteByUserId(userId);

        log.info("All sessions revoked and blacklisted for user: userId={}, count={}", userId, sessions.size());

        return sessions.size();
    }

    /**
     * 토큰으로 세션 무효화 (단일 로그아웃)
     * - Redis: 블랙리스트 추가 (필터 검증용, AOF로 영속성 보장)
     * - DB: 세션 삭제
     * - Audit: 로그 기록 (감사 추적)
     */
    @Transactional
    public boolean deleteSessionByToken(String refreshToken) {
        String tokenHash = cryptoUtil.hashRefreshToken(refreshToken);
        RefreshTokenSession session = sessionRepository.findByRefreshTokenHash(tokenHash).orElse(null);

        if (session != null) {
            // 1. Redis: 블랙리스트 추가 (필수)
            blacklistService.addToBlacklist(refreshToken);

            // 2. 감사 로그: 토큰으로 세션 무효화 (비동기 DB 저장)
            auditService.logSessionRevokedByToken(session.getSessionId(), session.getUserId(), session.getDeviceName(), "TOKEN_LOGOUT");

            // 3. DB: 세션 삭제
            sessionRepository.delete(session);

            log.info("Session revoked and blacklisted by token: sessionId={}", session.getSessionId());

            return true;
        }

        return false;
    }

    /**
     * 만료된 세션 정리 (배치용)
     */
    @Transactional
    public void cleanExpiredSessions() {
        LocalDateTime expiryDate = LocalDateTime.now().minusDays(14);
        sessionRepository.deleteByCreatedAtBefore(expiryDate);
        log.info("Expired sessions cleaned (before: {})", expiryDate);
    }

    /**
     * 클라이언트 IP 추출
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_FORWARDED");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // X-Forwarded-For에 여러 IP가 있을 경우 첫 번째 IP 사용
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }

    /**
     * User-Agent에서 기기명 추출
     */
    private String extractDeviceName(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");

        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown Device";
        }

        // 간단한 파싱 (클라이언트에서 device_name을 보내주는 게 더 정확함)
        if (userAgent.contains("iPhone")) {
            return "iPhone";
        } else if (userAgent.contains("iPad")) {
            return "iPad";
        } else if (userAgent.contains("Android")) {
            // Android 기기명 추출 (예: SM-G950N)
            int buildIndex = userAgent.indexOf("Build/");
            if (buildIndex > 0) {
                String beforeBuild = userAgent.substring(0, buildIndex).trim();
                int lastSemicolon = beforeBuild.lastIndexOf(";");
                if (lastSemicolon > 0) {
                    return beforeBuild.substring(lastSemicolon + 1).trim();
                }
            }
            return "Android Device";
        } else if (userAgent.contains("Mac")) {
            return "Mac";
        } else if (userAgent.contains("Windows")) {
            return "Windows PC";
        } else if (userAgent.contains("Linux")) {
            return "Linux PC";
        }

        return "Unknown Device";
    }
}
