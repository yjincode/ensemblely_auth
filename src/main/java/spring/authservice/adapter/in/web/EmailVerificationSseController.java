package spring.authservice.adapter.in.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import spring.authservice.application.service.EmailVerificationSseService;

/**
 * 이메일 인증 SSE 컨트롤러
 * - 실시간 이메일 인증 완료 알림
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class EmailVerificationSseController {

    private final EmailVerificationSseService sseService;

    @GetMapping(value = "/verify-stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter waitForVerification(@RequestParam String email) {
        log.info("SSE 인증 대기 요청: {}", email);
        return sseService.createEmitter(email);
    }

    /**
     * 활성 SSE 연결 수 조회 (모니터링용)
     */
    @GetMapping("/verify-stream/count")
    public int getActiveConnectionCount() {
        return sseService.getActiveConnectionCount();
    }
}
