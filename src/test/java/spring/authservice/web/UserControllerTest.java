package spring.authservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import spring.authservice.domain.UserDto;
import spring.authservice.service.UserService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @Test
    @DisplayName("회원가입 성공")
    void register_success() throws Exception {
        // given
        UserDto.LocalJoinRequest request = UserDto.LocalJoinRequest.builder()
                .userId("testuser")
                .email("test@example.com")
                .username("테스트유저")
                .nickname("테스트")
                .password("password123")
                .build();

        UserDto.LocalJoinResponse response = UserDto.LocalJoinResponse.builder()
                .success(true)
                .message("회원가입 성공")
                .token("test-jwt-token")
                .build();

        when(userService.registerUser(any(UserDto.LocalJoinRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("회원가입 성공"))
                .andExpect(jsonPath("$.token").value("test-jwt-token"));
    }

    @Test
    @DisplayName("아이디 중복 체크 - 사용 가능")
    void checkUserId_available() throws Exception {
        // given
        UserDto.IsUserIdAvailableResponse response = UserDto.IsUserIdAvailableResponse.builder()
                .success(true)
                .message("사용 가능한 아이디입니다")
                .build();

        when(userService.isUserIdAvailable(anyString()))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(get("/auths/check-userid")
                        .param("userId", "testuser"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("사용 가능한 아이디입니다"));
    }

    @Test
    @DisplayName("로그인 성공")
    void login_success() throws Exception {
        // given
        UserDto.LoginRequest request = UserDto.LoginRequest.builder()
                .userId("testuser")
                .password("password123")
                .build();

        UserDto.LoginResponse response = UserDto.LoginResponse.builder()
                .success(true)
                .message("로그인 성공")
                .token("test-jwt-token")
                .build();

        when(userService.authenticateUser(any(UserDto.LoginRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그인 성공"))
                .andExpect(jsonPath("$.token").value("test-jwt-token"));
    }

    @Test
    @DisplayName("이메일 인증 코드 발송")
    void sendEmailVerification() throws Exception {
        // given
        UserDto.SendEmailVerificationRequest request = UserDto.SendEmailVerificationRequest.builder()
                .email("test@example.com")
                .build();

        UserDto.SendEmailVerificationResponse response = UserDto.SendEmailVerificationResponse.builder()
                .success(true)
                .message("인증 코드가 발송되었습니다")
                .build();

        when(userService.sendEmailVerification(any(UserDto.SendEmailVerificationRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/email/send-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("인증 코드가 발송되었습니다"));
    }

    @Test
    @DisplayName("이메일 인증 코드 검증")
    void verifyEmailCode() throws Exception {
        // given
        UserDto.VerifyEmailCodeRequest request = UserDto.VerifyEmailCodeRequest.builder()
                .email("test@example.com")
                .verificationCode("123456")
                .build();

        UserDto.VerifyEmailCodeResponse response = UserDto.VerifyEmailCodeResponse.builder()
                .success(true)
                .message("이메일 인증이 완료되었습니다")
                .build();

        when(userService.verifyEmailCode(any(UserDto.VerifyEmailCodeRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/email/verify-code")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("이메일 인증이 완료되었습니다"));
    }

    @Test
    @DisplayName("이메일 토큰으로 인증 (HTML 페이지 반환)")
    void verifyEmailByToken() throws Exception {
        // given
        when(userService.verifyEmailByTokenForHtml(anyString(), any()))
                .thenReturn("email-verification-result");

        // when & then
        mockMvc.perform(get("/auths/verify-email")
                        .param("token", "test-token"))
                .andExpect(status().isOk())
                .andExpect(view().name("email-verification-result"));
    }

    @Test
    @DisplayName("비밀번호 재설정 코드 발송")
    void sendPasswordResetCode() throws Exception {
        // given
        UserDto.SendPasswordResetRequest request = UserDto.SendPasswordResetRequest.builder()
                .email("test@example.com")
                .build();

        UserDto.SendPasswordResetResponse response = UserDto.SendPasswordResetResponse.builder()
                .success(true)
                .message("비밀번호 재설정 코드가 발송되었습니다")
                .build();

        when(userService.sendPasswordResetCode(any(UserDto.SendPasswordResetRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/password/reset/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("비밀번호 재설정 코드가 발송되었습니다"));
    }

    @Test
    @DisplayName("비밀번호 재설정 코드 검증")
    void verifyPasswordResetCode() throws Exception {
        // given
        UserDto.VerifyPasswordResetCodeRequest request = UserDto.VerifyPasswordResetCodeRequest.builder()
                .email("test@example.com")
                .verificationCode("123456")
                .build();

        UserDto.VerifyPasswordResetCodeResponse response = UserDto.VerifyPasswordResetCodeResponse.builder()
                .success(true)
                .message("인증이 완료되었습니다")
                .build();

        when(userService.verifyPasswordResetCode(any(UserDto.VerifyPasswordResetCodeRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/password/reset/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("인증이 완료되었습니다"));
    }

    @Test
    @DisplayName("비밀번호 변경")
    void changePassword() throws Exception {
        // given
        UserDto.ChangePasswordRequest request = UserDto.ChangePasswordRequest.builder()
                .email("test@example.com")
                .newPassword("newPassword123")
                .build();

        UserDto.ChangePasswordResponse response = UserDto.ChangePasswordResponse.builder()
                .success(true)
                .message("비밀번호가 변경되었습니다")
                .build();

        when(userService.changePassword(any(UserDto.ChangePasswordRequest.class)))
                .thenReturn(ResponseEntity.ok(response));

        // when & then
        mockMvc.perform(post("/auths/password/reset/change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("비밀번호가 변경되었습니다"));
    }
}
