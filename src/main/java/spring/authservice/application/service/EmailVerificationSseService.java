package spring.authservice.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 이메일 인증 SSE 관리 서비스
 * - 이메일 인증 대기 중인 사용자에게 실시간 알림
 * - Redis Pub/Sub 기반
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationSseService {

    private final RedisMessageListenerContainer redisMessageListenerContainer;

    // 이메일별 Emitter 관리 (동시성 제어)
    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();

    private static final long SSE_TIMEOUT = 5 * 60 * 1000L; // 5분
    private static final String CHANNEL_PREFIX = "email_verified:";

    /**
     * 이메일 인증 대기 SSE 연결
     */
    public SseEmitter createEmitter(String email) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);

        // Emitter 저장
        emitters.put(email, emitter);
        log.info("SSE 연결 생성: {}", email);

        // Redis Pub/Sub 구독
        String channel = CHANNEL_PREFIX + email;
        MessageListener listener = createMessageListener(email, emitter);
        redisMessageListenerContainer.addMessageListener(listener, new ChannelTopic(channel));

        // 연결 종료 시 정리
        emitter.onCompletion(() -> {
            log.info("SSE 연결 정상 종료: {}", email);
            cleanup(email, listener);
        });

        emitter.onTimeout(() -> {
            log.warn("SSE 연결 타임아웃: {}", email);
            cleanup(email, listener);
        });

        emitter.onError((ex) -> {
            // AsyncRequestNotUsableException, Broken pipe 등은 정상 (클라이언트 연결 해제)
            if (ex instanceof org.springframework.web.context.request.async.AsyncRequestNotUsableException) {
                log.debug("SSE 연결 해제 (클라이언트가 연결 종료): {}", email);
            } else {
                log.warn("SSE 연결 에러: {} - {}", email, ex.getMessage());
            }
            cleanup(email, listener);
        });

        // 초기 연결 확인 메시지
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("SSE 연결됨"));
        } catch (IOException e) {
            log.error("SSE 초기 메시지 전송 실패: {}", email, e);
            cleanup(email, listener);
        }

        return emitter;
    }

    /**
     * Redis 메시지 리스너 생성
     */
    private MessageListener createMessageListener(String email, SseEmitter emitter) {
        return (Message message, byte[] pattern) -> {
            try {
                log.info("이메일 인증 완료 알림 수신: {}", email);

                // 프론트엔드에 인증 완료 이벤트 전송
                emitter.send(SseEmitter.event()
                        .name("verified")
                        .data("SUCCESS"));

                // 연결 종료
                emitter.complete();
                log.info("SSE 인증 완료 전송 성공: {}", email);

            } catch (IllegalStateException e) {
                // 클라이언트가 이미 연결을 끊은 경우 (정상)
                log.debug("SSE 연결이 이미 종료됨 (클라이언트 연결 해제): {}", email);
            } catch (IOException e) {
                // Broken pipe 등 네트워크 에러 (정상)
                log.debug("SSE 전송 실패 (클라이언트 연결 끊김): {}", email);
            } catch (Exception e) {
                log.error("SSE 메시지 처리 중 예상치 못한 에러: {}", email, e);
            }
        };
    }

    /**
     * Emitter 및 리스너 정리
     */
    private void cleanup(String email, MessageListener listener) {
        emitters.remove(email);
        redisMessageListenerContainer.removeMessageListener(listener);
        log.debug("SSE 리소스 정리 완료: {}", email);
    }

    /**
     * 활성 연결 수 조회 (모니터링용)
     */
    public int getActiveConnectionCount() {
        return emitters.size();
    }
}
