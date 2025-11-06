package spring.authservice.adapter.in.web;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import spring.authservice.application.port.in.*;
import spring.authservice.domain.vo.UserDto;

/**
 * 사용자 인증 API 컨트롤러
 * - 회원가입, 로그인, 이메일 인증, 비밀번호 재설정
 */

@Controller
@RequiredArgsConstructor
public class UserController {

    private final RegisterUserUseCase registerUserUseCase;
    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final ManageSessionUseCase manageSessionUseCase;
    private final ManageTokenUseCase manageTokenUseCase;
    private final ResetPasswordUseCase resetPasswordUseCase;
    private final UpdateProfileUseCase updateProfileUseCase;
    private final SocialLoginUseCase socialLoginUseCase;
    private final MergeSocialAccountUseCase mergeSocialAccountUseCase;

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

    @PostMapping("/auths/logout")
    @ResponseBody
    public ResponseEntity<UserDto.LogoutResponse> logout(
            @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        return manageTokenUseCase.logout(refreshToken);
    }

    @PostMapping("/auths/social/login")
    @ResponseBody
    public ResponseEntity<UserDto.SocialLoginResponse> socialLogin(
            @RequestBody UserDto.SocialLoginRequest request,
            HttpServletRequest httpRequest) {
        return socialLoginUseCase.socialLogin(request, httpRequest);
    }

    @PostMapping("/auths/social/merge")
    @ResponseBody
    public ResponseEntity<UserDto.SocialMergeResponse> mergeSocialAccount(
            @RequestBody UserDto.SocialMergeRequest request,
            HttpServletRequest httpRequest) {
        return mergeSocialAccountUseCase.mergeSocialAccount(request, httpRequest);
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

    @PostMapping("/auths/password/reset")
    @ResponseBody
    public ResponseEntity<UserDto.ResetPasswordResponse> resetPassword(
            @RequestBody UserDto.ResetPasswordRequest request) {
        return resetPasswordUseCase.resetPassword(request);
    }

    // === 세션 관리 API ===

    @GetMapping("/me/sessions")
    @ResponseBody
    public ResponseEntity<UserDto.GetSessionsResponse> getSessions(
            @RequestHeader(value = "X-User-Id") Long userId) {
        return manageSessionUseCase.getSessions(userId);
    }

    @DeleteMapping("/me/sessions/{sessionId}")
    @ResponseBody
    public ResponseEntity<UserDto.DeleteSessionResponse> deleteSession(
            @PathVariable String sessionId,
            @RequestHeader(value = "X-User-Id") Long userId) {
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
            @RequestHeader(value = "X-User-Id") Long userId) {
        return manageSessionUseCase.deleteAllSessions(userId);
    }

    // === 프로필 관리 API ===

    /**
     * 비밀번호 변경 (로그인 상태)
     * @param request 비밀번호 변경 요청
     * @param userId 사용자 ID (게이트웨이에서 전달)
     * @return 비밀번호 변경 결과
     */
    @PutMapping("/me/password")
    @ResponseBody
    public ResponseEntity<UserDto.UpdatePasswordResponse> updatePassword(
            @RequestBody UserDto.UpdatePasswordRequest request,
            @RequestHeader(value = "X-User-Id") Long userId) {
        return updateProfileUseCase.updatePassword(userId, request);
    }

    /**
     * 프로필 이미지 업로드
     * @param file 업로드할 이미지 파일 (multipart/form-data)
     * @param userId 사용자 ID (게이트웨이에서 전달)
     * @return 업로드 결과
     */
    @PostMapping("/me/profile/image")
    @ResponseBody
    public ResponseEntity<UserDto.UploadProfileImageResponse> uploadProfileImage(
            @RequestParam("file") MultipartFile file,
            @RequestHeader(value = "X-User-Id") Long userId) {
        return updateProfileUseCase.uploadProfileImage(userId, file);
    }

    /**
     * 프로필 이미지 삭제
     * @param userId 사용자 ID (게이트웨이에서 전달)
     * @return 삭제 결과
     */
    @DeleteMapping("/me/profile/image")
    @ResponseBody
    public ResponseEntity<UserDto.DeleteProfileImageResponse> deleteProfileImage(
            @RequestHeader(value = "X-User-Id") Long userId) {
        return updateProfileUseCase.deleteProfileImage(userId);
    }
}
