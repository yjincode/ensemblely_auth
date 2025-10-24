package spring.authservice.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 아이디로 사용자 찾기 (로그인용)
    Optional<User> findByUserId(String userId);
    
    // 소셜 로그인 사용자 찾기
    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);

    // 아이디 중복 체크
    boolean existsByUserId(String userId);
    
    // 이메일로 사용자 찾기 (이메일 로그인/소셜 로그인용)
    Optional<User> findByEmail(String email);
    
    // 이메일 중복 체크 (회원가입용)
    boolean existsByEmail(String email);

}