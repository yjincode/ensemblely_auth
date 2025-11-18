package spring.authservice.adapter.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 이메일로 사용자 찾기 (이메일 로그인용)
    Optional<User> findByEmail(String email);

    // 이메일로 모든 provider 사용자 찾기
    List<User> findAllByEmail(String email);

    // 이메일 + 특정 Provider들로 사용자 찾기 (효율적인 조회)
    List<User> findByEmailAndAuthProviderIn(String email, List<AuthProviderEnum> providers);

    // 이메일 + Provider로 사용자 찾기 (소셜 로그인용)
    Optional<User> findByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    // 이메일 중복 체크 (전체)
    boolean existsByEmail(String email);

    // 이메일 + Provider 중복 체크 (소셜 가입용)
    boolean existsByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    // 소셜 로그인 사용자 찾기
    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);

}