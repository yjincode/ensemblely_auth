package spring.authservice.adapter.out.persistence;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.User;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * UserPersistenceAdapter 테스트
 *
 * 헥사고날 아키텍처의 이점:
 * - Adapter가 Port 인터페이스를 올바르게 구현하는지 테스트
 * - JPA Repository를 Mock으로 대체하여 단위 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserPersistenceAdapter 단위 테스트")
class UserPersistenceAdapterTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserPersistenceAdapter userPersistenceAdapter;

    private User mockUser;

    @BeforeEach
    void setUp() {
        mockUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .username("testuser")
                .nickname("테스트유저")
                .password("$2a$10$encrypted")
                .authProvider(AuthProviderEnum.EMAIL)
                .accountVerified(true)
                .build();
    }

    @Test
    @DisplayName("사용자 저장 성공")
    void save_Success() {
        // Given
        when(userRepository.save(any(User.class))).thenReturn(mockUser);

        // When
        User savedUser = userPersistenceAdapter.save(mockUser);

        // Then
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo("test@example.com");
        assertThat(savedUser.getNickname()).isEqualTo("테스트유저");

        verify(userRepository, times(1)).save(mockUser);
    }

    @Test
    @DisplayName("이메일로 사용자 조회 성공")
    void findByEmail_Success() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(mockUser));

        // When
        Optional<User> foundUser = userPersistenceAdapter.findByEmail("test@example.com");

        // Then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");

        verify(userRepository, times(1)).findByEmail("test@example.com");
    }

    @Test
    @DisplayName("이메일로 사용자 조회 실패 - 존재하지 않음")
    void findByEmail_NotFound() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When
        Optional<User> foundUser = userPersistenceAdapter.findByEmail("notfound@example.com");

        // Then
        assertThat(foundUser).isEmpty();

        verify(userRepository, times(1)).findByEmail("notfound@example.com");
    }

    @Test
    @DisplayName("ID로 사용자 조회 성공")
    void findById_Success() {
        // Given
        when(userRepository.findById(anyLong())).thenReturn(Optional.of(mockUser));

        // When
        Optional<User> foundUser = userPersistenceAdapter.findById(1L);

        // Then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getId()).isEqualTo(1L);

        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("이메일 중복 체크 - 존재함")
    void existsByEmail_True() {
        // Given
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When
        boolean exists = userPersistenceAdapter.existsByEmail("test@example.com");

        // Then
        assertThat(exists).isTrue();

        verify(userRepository, times(1)).existsByEmail("test@example.com");
    }

    @Test
    @DisplayName("이메일 중복 체크 - 존재하지 않음")
    void existsByEmail_False() {
        // Given
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        // When
        boolean exists = userPersistenceAdapter.existsByEmail("new@example.com");

        // Then
        assertThat(exists).isFalse();

        verify(userRepository, times(1)).existsByEmail("new@example.com");
    }

    @Test
    @DisplayName("소셜 로그인 사용자 조회")
    void findBySocialIdAndAuthProvider_Success() {
        // Given
        String socialId = "google-123456";
        AuthProviderEnum provider = AuthProviderEnum.GOOGLE;

        when(userRepository.findBySocialIdAndAuthProvider(socialId, provider))
                .thenReturn(Optional.of(mockUser));

        // When
        Optional<User> foundUser = userPersistenceAdapter
                .findBySocialIdAndAuthProvider(socialId, provider);

        // Then
        assertThat(foundUser).isPresent();

        verify(userRepository, times(1)).findBySocialIdAndAuthProvider(socialId, provider);
    }
}
