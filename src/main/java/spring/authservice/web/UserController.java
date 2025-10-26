package spring.authservice.web;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import spring.authservice.domain.UserDto;
import spring.authservice.service.UserService;

/**
 * 사용자 인증 API 컨트롤러
 * - 회원가입, 로그인, 이메일 인증, 비밀번호 재설정
 */

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // === 인증/인가 API ===

    @PostMapping("/auths/register")
    @ResponseBody
    public ResponseEntity<UserDto.LocalJoinResponse> register(
            @RequestBody UserDto.LocalJoinRequest request) {
        return userService.registerUser(request);
    }

    @GetMapping("/auths/check-userid")
    @ResponseBody
    public ResponseEntity<UserDto.IsUserIdAvailableResponse> checkUserId(
            @RequestParam String userId) {
        return userService.isUserIdAvailable(userId);
    }

    @PostMapping("/auths/login")
    @ResponseBody
    public ResponseEntity<UserDto.LoginResponse> login(
            @RequestBody UserDto.LoginRequest request) {
        return userService.authenticateUser(request);
    }

    @PostMapping("/auths/email/send-verification")
    @ResponseBody
    public ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(
            @RequestBody UserDto.SendEmailVerificationRequest request) {
        return userService.sendEmailVerification(request);
    }

    @PostMapping("/auths/email/verify-code")
    @ResponseBody
    public ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(
            @RequestBody UserDto.VerifyEmailCodeRequest request) {
        return userService.verifyEmailCode(request);
    }

    @GetMapping("/auths/verify-email")
    public String verifyEmailByToken(@RequestParam String token, Model model) {
        return userService.verifyEmailByTokenForHtml(token, model);
    }

    // === 비밀번호 재설정 API ===

    @PostMapping("/auths/password/reset/send")
    @ResponseBody
    public ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(
            @RequestBody UserDto.SendPasswordResetRequest request) {
        return userService.sendPasswordResetCode(request);
    }

    @PostMapping("/auths/password/reset/verify")
    @ResponseBody
    public ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(
            @RequestBody UserDto.VerifyPasswordResetCodeRequest request) {
        return userService.verifyPasswordResetCode(request);
    }

    @PostMapping("/auths/password/reset/change")
    @ResponseBody
    public ResponseEntity<UserDto.ChangePasswordResponse> changePassword(
            @RequestBody UserDto.ChangePasswordRequest request,
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        return userService.changePassword(request, refreshToken);
    }

    // === 토큰 관리 API ===

    @PostMapping("/auths/refresh")
    @ResponseBody
    public ResponseEntity<UserDto.RefreshTokenResponse> refreshToken(
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        return userService.refreshAccessToken(refreshToken);
    }

    @PostMapping("/auths/logout")
    @ResponseBody
    public ResponseEntity<UserDto.LogoutResponse> logout(
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        return userService.logout(refreshToken);
    }
}
