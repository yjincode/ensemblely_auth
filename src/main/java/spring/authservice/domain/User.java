package spring.authservice.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String socialId;

    @Column(unique = true)
    private String userId;

    @Column(unique = true)
    private String email;

    @Column
    private String username;

    private String nickname;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    private AuthProviderEnum authProvider;

    private boolean accountVerified;

    // 프로필 이미지 URL (추후 프로필 수정 시 추가 가능)
    @Column(length = 500)
    private String profileImageUrl;

    // 워크스페이스 생성 제한 (기본 2개, 추후 구독제로 확장)
    @Column(nullable = false)
    @Builder.Default
    private Integer maxWorkspaces = 2;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

}