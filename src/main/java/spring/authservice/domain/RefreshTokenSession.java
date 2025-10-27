package spring.authservice.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Refresh Token 세션 엔티티
 * - 사용자의 로그인 기기 정보 관리
 * - 세션 목록 조회, 특정 기기 로그아웃 등에 사용
 */
@Entity
@Table(name = "refresh_token_sessions", indexes = {
        @Index(name = "idx_user_id", columnList = "user_id"),
        @Index(name = "idx_token_hash", columnList = "refresh_token_hash")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder(toBuilder = true)
public class RefreshTokenSession {

    @Id
    @Column(columnDefinition = "uuid")
    private UUID sessionId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "refresh_token_hash", nullable = false, length = 64)
    private String refreshTokenHash;  // HMAC-SHA256 (hex, 64자) - 검색용

    @Column(name = "encrypted_token", nullable = false, length = 512)
    private String encryptedToken;  // AES-256 암호화된 Refresh Token - 블랙리스트 추가용

    @Column(name = "device_name", length = 100)
    private String deviceName;  // "홍길동의 MacBook", "SM-P200"

    @Column(name = "ip_address", length = 255)
    private String ipAddress;  // AES-256 암호화된 IP

    @Column(name = "country", length = 2)
    private String country;  // "KR", "US" (ISO 3166-1 alpha-2)

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at", nullable = false)
    private LocalDateTime lastUsedAt;

    @Builder.Default
    @Column(name = "revoked", nullable = false)
    private boolean revoked = false;  // 세션 무효화 여부

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;  // 무효화 시각

    @PrePersist
    protected void onCreate() {
        if (sessionId == null) {
            sessionId = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (lastUsedAt == null) {
            lastUsedAt = LocalDateTime.now();
        }
    }

    /**
     * 마지막 사용 시각 업데이트
     */
    public void updateLastUsedAt() {
        this.lastUsedAt = LocalDateTime.now();
    }
}
