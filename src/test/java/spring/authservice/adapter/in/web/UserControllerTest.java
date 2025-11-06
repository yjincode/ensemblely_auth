package spring.authservice.adapter.in.web;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import spring.authservice.application.port.in.AuthenticateUserUseCase;
import spring.authservice.application.port.in.ManageSessionUseCase;
import spring.authservice.application.port.in.RegisterUserUseCase;
import spring.authservice.application.port.in.ResetPasswordUseCase;
import spring.authservice.application.port.in.QueryUserInfoUseCase;
import spring.authservice.domain.vo.UserDto;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * UserController 테스트
 *
 * 헥사고날 아키텍처의 이점:
 * - Port(인터페이스)를 Mock으로 대체하여 테스트
 * - 실제 Service 구현체 불필요 (의존성 7개 필요 없음)
 * - 빠르고 가볍게 테스트 가능
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserController 단위 테스트 (헥사고날 아키텍처)")
class UserControllerTest {

    @Mock
    private RegisterUserUseCase registerUserUseCase;

    @Mock
    private AuthenticateUserUseCase authenticateUserUseCase;

    @Mock
    private ManageSessionUseCase manageSessionUseCase;

    @Mock
    private ResetPasswordUseCase resetPasswordUseCase;

    @Mock
    private QueryUserInfoUseCase queryUserInfoUseCase;

    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private UserController userController;

    private UserDto.LocalJoinRequest joinRequest;
    private UserDto.LoginRequest loginRequest;

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
    }

    @Test
    @DisplayName("회원가입 성공 - Port Mock 사용으로 간단한 테스트")
    void register_Success() {
        // Given
        UserDto.LocalJoinResponse expectedResponse = UserDto.LocalJoinResponse.builder()
                .success(true)
                .message("회원가입이 완료되었습니다")
                .token("mock-jwt-token")
                .build();

        when(registerUserUseCase.registerUser(any(), any()))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body(expectedResponse));

        // When
        ResponseEntity<UserDto.LocalJoinResponse> response =
                userController.register(joinRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getToken()).isEqualTo("mock-jwt-token");

        // 검증: registerUserUseCase가 1번 호출되었는지
        verify(registerUserUseCase, times(1)).registerUser(any(), any());
    }

    @Test
    @DisplayName("로그인 성공")
    void login_Success() {
        // Given
        UserDto.LoginResponse expectedResponse = UserDto.LoginResponse.builder()
                .success(true)
                .message("로그인이 완료되었습니다")
                .token("mock-jwt-token")
                .build();

        when(authenticateUserUseCase.authenticateUser(any(), any()))
                .thenReturn(ResponseEntity.ok(expectedResponse));

        // When
        ResponseEntity<UserDto.LoginResponse> response =
                userController.login(loginRequest, httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getToken()).isEqualTo("mock-jwt-token");

        verify(authenticateUserUseCase, times(1)).authenticateUser(any(), any());
    }

    @Test
    @DisplayName("이메일 인증 코드 발송 성공")
    void sendEmailVerification_Success() {
        // Given
        UserDto.SendEmailVerificationRequest request = UserDto.SendEmailVerificationRequest.builder()
                .email("test@example.com")
                .build();

        UserDto.SendEmailVerificationResponse expectedResponse =
                UserDto.SendEmailVerificationResponse.builder()
                        .success(true)
                        .message("인증 코드가 이메일로 발송되었습니다")
                        .build();

        when(registerUserUseCase.sendEmailVerification(any()))
                .thenReturn(ResponseEntity.ok(expectedResponse));

        // When
        ResponseEntity<UserDto.SendEmailVerificationResponse> response =
                userController.sendEmailVerification(request);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();

        verify(registerUserUseCase, times(1)).sendEmailVerification(any());
    }

    @Test
    @DisplayName("세션 조회 - 인증된 사용자")
    void getSessions_Success() {
        // Given
        Long userId = 1L;

        UserDto.GetSessionsResponse expectedResponse = UserDto.GetSessionsResponse.builder()
                .success(true)
                .message("세션 조회 성공")
                .sessions(java.util.List.of())
                .build();

        when(manageSessionUseCase.getSessions(userId))
                .thenReturn(ResponseEntity.ok(expectedResponse));

        // When
        ResponseEntity<UserDto.GetSessionsResponse> response =
                userController.getSessions(userId);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();

        verify(manageSessionUseCase, times(1)).getSessions(userId);
    }

    @Test
    @DisplayName("특정 세션 삭제 성공")
    void deleteSession_Success() {
        // Given
        String sessionId = UUID.randomUUID().toString();
        Long userId = 1L;

        UserDto.DeleteSessionResponse expectedResponse = UserDto.DeleteSessionResponse.builder()
                .success(true)
                .message("세션이 삭제되었습니다")
                .build();

        when(manageSessionUseCase.deleteSession(eq(userId), any(UUID.class)))
                .thenReturn(ResponseEntity.ok(expectedResponse));

        // When
        ResponseEntity<UserDto.DeleteSessionResponse> response =
                userController.deleteSession(sessionId, userId);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();

        verify(manageSessionUseCase, times(1)).deleteSession(eq(userId), any(UUID.class));
    }

    @Test
    @DisplayName("비밀번호 재설정 코드 발송 성공")
    void sendPasswordResetCode_Success() {
        // Given
        UserDto.SendPasswordResetRequest request = UserDto.SendPasswordResetRequest.builder()
                .email("test@example.com")
                .build();

        UserDto.SendPasswordResetResponse expectedResponse =
                UserDto.SendPasswordResetResponse.builder()
                        .success(true)
                        .message("인증 코드가 이메일로 발송되었습니다")
                        .build();

        when(resetPasswordUseCase.sendPasswordResetCode(any()))
                .thenReturn(ResponseEntity.ok(expectedResponse));

        // When
        ResponseEntity<UserDto.SendPasswordResetResponse> response =
                userController.sendPasswordResetCode(request);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();

        verify(resetPasswordUseCase, times(1)).sendPasswordResetCode(any());
    }
}
