package spring.authservice.application.port.out;

import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.Optional;

/**
 * User 영속성 Port (Outbound)
 * - JPA, MongoDB, MyBatis 등 다양한 구현체 가능
 */
public interface UserPersistencePort {

    /**
     * 사용자 저장
     */
    User save(User user);

    /**
     * 이메일로 사용자 조회
     */
    Optional<User> findByEmail(String email);

    /**
     * 사용자 ID로 조회
     */
    Optional<User> findById(Long userId);

    /**
     * 이메일 중복 체크
     */
    boolean existsByEmail(String email);

    /**
     * 소셜 로그인 사용자 조회
     */
    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);
}
