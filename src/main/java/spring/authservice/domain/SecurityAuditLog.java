package spring.authservice.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 보안 감사 로그 엔티티
 * - 모든 보안 관련 이벤트를 영구 저장
 * - 법적 요구사항 준수 (최소 1년 보관)
 * - 변조 방지를 위한 INSERT ONLY (UPDATE/DELETE 불가)
 */
@Entity
@Table(name = "security_audit_log", indexes = {
        @Index(name = "idx_audit_user_time", columnList = "user_id, timestamp"),
        @Index(name = "idx_audit_event", columnList = "event_type"),
        @Index(name = "idx_audit_timestamp", columnList = "timestamp")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 이벤트 발생 시각
     */
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    /**
     * 이벤트 유형
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private AuditEventType eventType;

    /**
     * 사용자 ID (nullable: 비로그인 이벤트도 기록 가능)
     */
    @Column(name = "user_id")
    private Long userId;

    /**
     * 세션 ID (nullable: 세션이 없는 이벤트도 있음)
     */
    @Column(name = "session_id", columnDefinition = "uuid")
    private UUID sessionId;

    /**
     * 기기명 (예: "iPhone", "SM-G950N", "Windows PC")
     */
    @Column(name = "device_name", length = 100)
    private String deviceName;

    /**
     * IP 주소 (암호화 또는 마스킹 가능)
     */
    @Column(name = "ip_address", length = 255)
    private String ipAddress;

    /**
     * 국가 코드 (ISO 3166-1 alpha-2)
     */
    @Column(name = "country", length = 2)
    private String country;

    /**
     * 이벤트 발생 이유 (예: "USER_LOGOUT", "PASSWORD_CHANGE")
     */
    @Column(name = "reason", length = 100)
    private String reason;

    /**
     * 추가 상세 정보 (JSON 형태, PostgreSQL JSONB 권장)
     */
    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    /**
     * 요청 URI (블랙리스트 시도 등)
     */
    @Column(name = "request_uri", length = 500)
    private String requestUri;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }

    /**
     * 간단한 로그 생성 헬퍼 메서드
     */
    public static SecurityAuditLog of(AuditEventType eventType, Long userId) {
        return SecurityAuditLog.builder()
                .eventType(eventType)
                .userId(userId)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
