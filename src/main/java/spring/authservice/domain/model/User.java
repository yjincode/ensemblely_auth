package spring.authservice.domain.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_email_provider", columnNames = {"email", "auth_provider"})
        }
)
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

    @Column
    private String email;

    @Column
    private String username;

    private String nickname;

    @Column
    private String password;

    @Enumerated(EnumType.STRING)
    private AuthProviderEnum authProvider;

    // 프로필 이미지 URL (추후 프로필 수정 시 추가 가능)
    @Column(length = 500)
    private String profileImageUrl;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

}