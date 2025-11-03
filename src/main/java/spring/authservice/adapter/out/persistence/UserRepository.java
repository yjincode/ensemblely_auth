package spring.authservice.adapter.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 이메일로 사용자 찾기 (로그인/회원가입용)
    Optional<User> findByEmail(String email);

    // 이메일 중복 체크
    boolean existsByEmail(String email);

    // 소셜 로그인 사용자 찾기
    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);

}