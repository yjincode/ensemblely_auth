package spring.authservice.application.port.out;

import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.List;
import java.util.Optional;

public interface UserPersistencePort {

    User save(User user);

    Optional<User> findByEmail(String email);

    List<User> findAllByEmail(String email);

    List<User> findByEmailAndAuthProviderIn(String email, List<AuthProviderEnum> providers);

    Optional<User> findByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    Optional<User> findById(Long userId);

    boolean existsByEmail(String email);

    boolean existsByEmailAndAuthProvider(String email, AuthProviderEnum authProvider);

    Optional<User> findBySocialIdAndAuthProvider(String socialId, AuthProviderEnum authProvider);
}
