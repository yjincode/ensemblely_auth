package spring.authservice.adapter.in.web;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import spring.authservice.domain.vo.UserDto;
import spring.authservice.application.port.in.RegisterUserUseCase;
import spring.authservice.application.port.in.AuthenticateUserUseCase;
import spring.authservice.application.port.in.ManageTokenUseCase;
import spring.authservice.application.port.in.ManageSessionUseCase;
import spring.authservice.application.port.in.ResetPasswordUseCase;
import spring.authservice.application.port.in.QueryUserInfoUseCase;

/**
 * 사용자 인증 API 컨트롤러
 * - 회원가입, 로그인, 이메일 인증, 비밀번호 재설정
 */

@Controller
@RequiredArgsConstructor
public class UserController {

    private final RegisterUserUseCase registerUserUseCase;
    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final ManageTokenUseCase manageTokenUseCase;
    private final ManageSessionUseCase manageSessionUseCase;
    private final ResetPasswordUseCase resetPasswordUseCase;
    private final QueryUserInfoUseCase queryUserInfoUseCase;

    // === 인증/인가 API ===

    @PostMapping("/auths/register")
    @ResponseBody
    public ResponseEntity<UserDto.LocalJoinResponse> register(
            @RequestBody UserDto.LocalJoinRequest request,
            HttpServletRequest httpRequest) {
        return registerUserUseCase.registerUser(request, httpRequest);
    }

    @PostMapping("/auths/login")
    @ResponseBody
    public ResponseEntity<UserDto.LoginResponse> login(
            @RequestBody UserDto.LoginRequest request,
            HttpServletRequest httpRequest) {
        return authenticateUserUseCase.authenticateUser(request, httpRequest);
    }

    @PostMapping("/auths/email/send-verification")
    @ResponseBody
    public ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(
            @RequestBody UserDto.SendEmailVerificationRequest request) {
        return registerUserUseCase.sendEmailVerification(request);
    }

    @PostMapping("/auths/email/verify-code")
    @ResponseBody
    public ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(
            @RequestBody UserDto.VerifyEmailCodeRequest request) {
        return registerUserUseCase.verifyEmailCode(request);
    }

    @GetMapping("/auths/verify-email")
    public String verifyEmailByToken(@RequestParam String token, Model model) {
        return registerUserUseCase.verifyEmailByTokenForHtml(token, model);
    }

    // === 비밀번호 재설정 API ===

    @PostMapping("/auths/password/reset/send")
    @ResponseBody
    public ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(
            @RequestBody UserDto.SendPasswordResetRequest request) {
        return resetPasswordUseCase.sendPasswordResetCode(request);
    }

    @PostMapping("/auths/password/reset/verify")
    @ResponseBody
    public ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(
            @RequestBody UserDto.VerifyPasswordResetCodeRequest request) {
        return resetPasswordUseCase.verifyPasswordResetCode(request);
    }

    @PostMapping("/auths/password/reset/change")
    @ResponseBody
    public ResponseEntity<UserDto.ChangePasswordResponse> changePassword(
            @RequestBody UserDto.ChangePasswordRequest request,
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        return resetPasswordUseCase.changePassword(request, refreshToken);
    }

    // === 세션 관리 API ===

    @GetMapping("/me/sessions")
    @ResponseBody
    public ResponseEntity<UserDto.GetSessionsResponse> getSessions(
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(UserDto.GetSessionsResponse.builder()
                            .success(false)
                            .message("인증이 필요합니다")
                            .build());
        }

        Long userId = queryUserInfoUseCase.getUserIdFromRefreshToken(refreshToken);
        return manageSessionUseCase.getSessions(userId);
    }

    @DeleteMapping("/me/sessions/{sessionId}")
    @ResponseBody
    public ResponseEntity<UserDto.DeleteSessionResponse> deleteSession(
            @PathVariable String sessionId,
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(UserDto.DeleteSessionResponse.builder()
                            .success(false)
                            .message("인증이 필요합니다")
                            .build());
        }

        Long userId = queryUserInfoUseCase.getUserIdFromRefreshToken(refreshToken);
        try {
            return manageSessionUseCase.deleteSession(userId, java.util.UUID.fromString(sessionId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(UserDto.DeleteSessionResponse.builder()
                            .success(false)
                            .message("잘못된 세션 ID입니다")
                            .build());
        }
    }

    @DeleteMapping("/me/sessions")
    @ResponseBody
    public ResponseEntity<UserDto.DeleteAllSessionsResponse> deleteAllSessions(
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(UserDto.DeleteAllSessionsResponse.builder()
                            .success(false)
                            .message("인증이 필요합니다")
                            .deletedCount(0)
                            .build());
        }

        Long userId = queryUserInfoUseCase.getUserIdFromRefreshToken(refreshToken);
        return manageSessionUseCase.deleteAllSessions(userId);
    }
}
