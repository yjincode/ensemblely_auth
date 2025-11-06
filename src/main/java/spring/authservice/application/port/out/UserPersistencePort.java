package spring.authservice.application.port.out;

import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.Optional;

public interface UserPersistencePort {

    User save(User user);

    Optional<User> findByEmail(String email);

    Optional<User> findByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    Optional<User> findById(Long userId);

    boolean existsByEmail(String email);

    boolean existsByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);
}
