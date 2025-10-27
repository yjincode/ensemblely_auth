package spring.authservice.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import spring.authservice.service.RefreshTokenSessionService;

/**
 * 세션 정리 스케줄러
 * - 만료된 세션을 주기적으로 정리
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionCleanupScheduler {

    private final RefreshTokenSessionService sessionService;

    /**
     * 만료된 세션 정리
     * - 매일 새벽 3시 실행
     * - 14일 이상 된 세션 삭제 (Refresh Token 만료 기간과 동일)
     */
    @Scheduled(cron = "0 0 3 * * *")
    public void cleanExpiredSessions() {
        log.info("Starting expired session cleanup...");

        try {
            sessionService.cleanExpiredSessions();
            log.info("Expired session cleanup completed successfully");
        } catch (Exception e) {
            log.error("Failed to clean expired sessions: {}", e.getMessage(), e);
        }
    }
}
