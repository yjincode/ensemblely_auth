package spring.authservice.application.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import spring.authservice.application.port.out.EmailPort;
import spring.authservice.application.port.out.TokenCachePort;
import spring.authservice.application.port.out.UserPersistencePort;
import spring.authservice.domain.model.User;
import spring.authservice.domain.vo.UserDto;
import spring.authservice.util.JwtUtil;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * UserService 테스트
 *
 * 헥사고날 아키텍처의 이점:
 * - Outbound Port를 Mock으로 대체하여 테스트
 * - 실제 JPA Repository, Redis, Email 서비스 불필요
 * - 순수 비즈니스 로직만 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService 단위 테스트 (헥사고날 아키텍처)")
class UserServiceTest {

    @Mock
    private UserPersistencePort userPersistencePort;

    @Mock
    private TokenCachePort tokenCachePort;

    @Mock
    private EmailPort emailPort;

    @Mock
    private RefreshTokenSessionService sessionService;

    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private UserService userService;

    private UserDto.LocalJoinRequest joinRequest;
    private UserDto.LoginRequest loginRequest;
    private User mockUser;

    @BeforeEach
    void setUp() {
        joinRequest = UserDto.LocalJoinRequest.builder()
                .email("test@example.com")
                .username("testuser")
                .nickname("테스트유저")
                .password("password123")
                .build();

        loginRequest = UserDto.LoginRequest.builder()
                .email("test@example.com")
                .password("password123")
                .build();

        mockUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .username("testuser")
                .nickname("테스트유저")
                .password("$2a$10$encrypted")
                .accountVerified(true)
                .build();

        // RedisTemplate Mock 설정 (lenient - 모든 테스트에서 사용되지 않음)
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    @DisplayName("회원가입 성공 - 이메일 인증 완료된 경우")
    void registerUser_Success_EmailVerified() {
        // Given
        when(valueOperations.get("verified_email:" + joinRequest.getEmail()))
                .thenReturn("verified");
        when(userPersistencePort.existsByEmail(joinRequest.getEmail()))
                .thenReturn(false);
        when(bCryptPasswordEncoder.encode(anyString()))
                .thenReturn("$2a$10$encrypted");
        when(userPersistencePort.save(any(User.class)))
                .thenReturn(mockUser);
        when(jwtUtil.generateTokens(any(User.class)))
                .thenReturn(new String[]{"access-token", "refresh-token"});

        // When
        ResponseEntity<UserDto.LocalJoinResponse> response =
                userService.registerUser(joinRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("회원가입이 완료되었습니다");
        assertThat(response.getBody().getToken()).isEqualTo("access-token");

        // 검증: Port 메서드 호출 확인
        verify(userPersistencePort, times(1)).existsByEmail(joinRequest.getEmail());
        verify(userPersistencePort, times(1)).save(any(User.class));
        verify(jwtUtil, times(1)).generateTokens(any(User.class));
        verify(sessionService, times(1)).createSession(anyLong(), anyString(), any());
    }

    @Test
    @DisplayName("회원가입 실패 - 이메일 인증 미완료")
    void registerUser_Fail_EmailNotVerified() {
        // Given
        when(valueOperations.get("verified_email:" + joinRequest.getEmail()))
                .thenReturn(null);

        // When
        ResponseEntity<UserDto.LocalJoinResponse> response =
                userService.registerUser(joinRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("이메일 인증이 완료되지 않았습니다");

        // 검증: 이메일 인증 실패 시 저장 호출 안 됨
        verify(userPersistencePort, never()).save(any());
    }

    @Test
    @DisplayName("회원가입 실패 - 이메일 중복")
    void registerUser_Fail_EmailAlreadyExists() {
        // Given
        when(valueOperations.get("verified_email:" + joinRequest.getEmail()))
                .thenReturn("verified");
        when(userPersistencePort.existsByEmail(joinRequest.getEmail()))
                .thenReturn(true);

        // When
        ResponseEntity<UserDto.LocalJoinResponse> response =
                userService.registerUser(joinRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("이미 사용 중인 이메일입니다");

        verify(userPersistencePort, times(1)).existsByEmail(joinRequest.getEmail());
        verify(userPersistencePort, never()).save(any());
    }

    @Test
    @DisplayName("로그인 성공")
    void authenticateUser_Success() {
        // Given
        when(userPersistencePort.findByEmail(loginRequest.getEmail()))
                .thenReturn(Optional.of(mockUser));
        when(bCryptPasswordEncoder.matches(anyString(), anyString()))
                .thenReturn(true);
        when(jwtUtil.generateTokens(any(User.class)))
                .thenReturn(new String[]{"access-token", "refresh-token"});

        // When
        ResponseEntity<UserDto.LoginResponse> response =
                userService.authenticateUser(loginRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("로그인이 완료되었습니다");
        assertThat(response.getBody().getToken()).isEqualTo("access-token");

        verify(userPersistencePort, times(1)).findByEmail(loginRequest.getEmail());
        verify(jwtUtil, times(1)).generateTokens(mockUser);
        verify(sessionService, times(1)).createSession(anyLong(), anyString(), any());
    }

    @Test
    @DisplayName("로그인 실패 - 존재하지 않는 이메일")
    void authenticateUser_Fail_UserNotFound() {
        // Given
        when(userPersistencePort.findByEmail(loginRequest.getEmail()))
                .thenReturn(Optional.empty());

        // When
        ResponseEntity<UserDto.LoginResponse> response =
                userService.authenticateUser(loginRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("존재하지 않는 이메일입니다");

        verify(userPersistencePort, times(1)).findByEmail(loginRequest.getEmail());
        verify(jwtUtil, never()).generateTokens(any());
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호 불일치")
    void authenticateUser_Fail_WrongPassword() {
        // Given
        when(userPersistencePort.findByEmail(loginRequest.getEmail()))
                .thenReturn(Optional.of(mockUser));
        when(bCryptPasswordEncoder.matches(anyString(), anyString()))
                .thenReturn(false);

        // When
        ResponseEntity<UserDto.LoginResponse> response =
                userService.authenticateUser(loginRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("비밀번호가 일치하지 않습니다");

        verify(userPersistencePort, times(1)).findByEmail(loginRequest.getEmail());
        verify(jwtUtil, never()).generateTokens(any());
    }

    @Test
    @DisplayName("토큰 재발급 성공")
    void refreshAccessToken_Success() {
        // Given
        String refreshToken = "valid-refresh-token";
        Long userId = 1L;

        when(tokenCachePort.isBlacklisted(refreshToken)).thenReturn(false);
        when(jwtUtil.validateRefreshToken(refreshToken)).thenReturn(true);
        when(jwtUtil.getUserIdFromRefreshToken(refreshToken)).thenReturn(userId);
        when(userPersistencePort.findById(userId)).thenReturn(Optional.of(mockUser));
        when(jwtUtil.generateTokens(mockUser)).thenReturn(new String[]{"new-access-token", refreshToken});
        when(jwtUtil.getAccessTokenExpiresIn()).thenReturn(3600L);

        // When
        ResponseEntity<UserDto.RefreshTokenResponse> response =
                userService.refreshAccessToken(refreshToken);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getToken()).isEqualTo("new-access-token");
        assertThat(response.getBody().getAccessTokenExpiresIn()).isEqualTo(3600L);

        verify(tokenCachePort, times(1)).isBlacklisted(refreshToken);
        verify(jwtUtil, times(1)).validateRefreshToken(refreshToken);
        verify(userPersistencePort, times(1)).findById(userId);
        verify(sessionService, times(1)).updateLastUsedAt(refreshToken);
    }

    @Test
    @DisplayName("토큰 재발급 실패 - 블랙리스트에 등록된 토큰")
    void refreshAccessToken_Fail_Blacklisted() {
        // Given
        String refreshToken = "blacklisted-token";
        when(tokenCachePort.isBlacklisted(refreshToken)).thenReturn(true);

        // When
        ResponseEntity<UserDto.RefreshTokenResponse> response =
                userService.refreshAccessToken(refreshToken);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("로그아웃된 토큰입니다");

        verify(tokenCachePort, times(1)).isBlacklisted(refreshToken);
        verify(jwtUtil, never()).validateRefreshToken(anyString());
    }

    @Test
    @DisplayName("로그아웃 성공")
    void logout_Success() {
        // Given
        String refreshToken = "valid-refresh-token";

        // When
        ResponseEntity<UserDto.LogoutResponse> response = userService.logout(refreshToken);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("로그아웃되었습니다");

        // Note: sessionService.deleteSessionByToken internally handles blacklist addition
        verify(sessionService, times(1)).deleteSessionByToken(refreshToken);
    }
}
