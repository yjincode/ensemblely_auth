package spring.authservice.adapter.out.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring.authservice.application.port.out.UserPersistencePort;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.Optional;

/**
 * User 영속성 어댑터
 * - UserRepository를 통해 User 엔티티를 관리
 */
@Component
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserPersistencePort {

    private final UserRepository userRepository;

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public Optional<User> findById(Long userId) {
        return userRepository.findById(userId);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider) {
        return userRepository.findBySocialIdAndAuthProvider(socialId, authProvider);
    }
}
