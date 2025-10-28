package spring.authservice.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import spring.authservice.domain.RefreshTokenSession;
import spring.authservice.domain.UserDto;
import spring.authservice.domain.User;
import spring.authservice.domain.UserRepository;
import spring.authservice.util.JwtUtil;
import spring.authservice.util.PasswordValidator;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;
    private final RefreshTokenBlacklistService blacklistService;
    private final RefreshTokenSessionService sessionService;

    private static final String VERIFIED_EMAIL_PREFIX = "verified_email:";

    //회원가입
    public ResponseEntity<UserDto.LocalJoinResponse> registerUser(
            UserDto.LocalJoinRequest request,
            HttpServletRequest httpRequest) {

        // 1. 이메일 인증 여부 확인
        if (!isEmailVerified(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.LocalJoinResponse.builder()
                            .success(false)
                            .message("이메일 인증이 완료되지 않았습니다")
                            .build()
            );
        }

        // 2. 아이디 중복 확인
        if (userRepository.existsByUserId(request.getUserId())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    UserDto.LocalJoinResponse.builder()
                            .success(false)
                            .message("이미 사용 중인 아이디입니다")
                            .build()
            );
        }

        // 3. 비밀번호 유효성 검증
        String passwordValidationMessage = PasswordValidator.getValidationMessage(request.getPassword());
        if (passwordValidationMessage != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.LocalJoinResponse.builder()
                            .success(false)
                            .message(passwordValidationMessage)
                            .build()
            );
        }

        // 4. 사용자 생성 및 저장
        User user = request.toUser(bCryptPasswordEncoder);
        userRepository.save(user);

        // 5. 인증된 이메일 정보 삭제
        removeVerifiedEmail(request.getEmail());

        // 6. 토큰 생성 (자동 로그인)
        String[] tokens = jwtUtil.generateTokens(user);
        String accessToken = tokens[0];
        String refreshToken = tokens[1];

        // 7. 세션 저장
        sessionService.createSession(user.getId(), refreshToken, httpRequest);

        // 8. 리프레시 토큰을 HttpOnly 쿠키로 설정
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)  //TODO 배포환경에서는 true로 변경
                .path("/")
                .maxAge(30 * 24 * 60 * 60)  // 30일
                .sameSite("Strict")
                .build();

        return ResponseEntity.status(HttpStatus.CREATED)
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(UserDto.LocalJoinResponse.builder()
                        .success(true)
                        .message("회원가입이 완료되었습니다")
                        .token(accessToken)
                        .build()
                );
    }
    
    // 아이디 중복 체크 (실시간 검증용)
    public ResponseEntity<UserDto.IsUserIdAvailableResponse> isUserIdAvailable(String userId) {
        if (userRepository.existsByUserId(userId)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    UserDto.IsUserIdAvailableResponse.builder()
                            .success(false)
                            .message("사용중인 아이디입니다")
                            .build()
            );
        }

        return ResponseEntity.ok(
                UserDto.IsUserIdAvailableResponse.builder()
                        .success(true)
                        .message("사용 가능한 아이디입니다")
                        .build()
        );
    }
    
    // 로그인 (아이디 + 비밀번호)
    public ResponseEntity<UserDto.LoginResponse> authenticateUser(
            UserDto.LoginRequest request,
            HttpServletRequest httpRequest) {
        // 1. 사용자 존재 여부 확인
        User user = userRepository.findByUserId(request.getUserId())
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.LoginResponse.builder()
                            .success(false)
                            .message("존재하지 않는 아이디입니다")
                            .build()
            );
        }

        // 2. 비밀번호 검증 (대소문자 구분 안함)
        if (!bCryptPasswordEncoder.matches(request.getPassword().toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.LoginResponse.builder()
                            .success(false)
                            .message("비밀번호가 일치하지 않습니다")
                            .build()
            );
        }

        // 3. JWT 토큰 생성
        String[] tokens = jwtUtil.generateTokens(user);
        String accessToken = tokens[0];
        String refreshToken = tokens[1];

        // 4. 세션 저장
        sessionService.createSession(user.getId(), refreshToken, httpRequest);

        // 5. 리프레시 토큰을 HttpOnly 쿠키로 설정
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)  //TODO 배포환경에서는 true로 변경
                .path("/")
                .maxAge(30 * 24 * 60 * 60)  // 30일
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(UserDto.LoginResponse.builder()
                        .success(true)
                        .message("로그인이 완료되었습니다")
                        .token(accessToken)
                        .build()
                );
    }
    
    // 이메일 인증 코드 발송
    public ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(UserDto.SendEmailVerificationRequest request) {
        String email = request.getEmail();

        // 1. 이메일 중복 체크
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    UserDto.SendEmailVerificationResponse.builder()
                            .success(false)
                            .message("이미 가입된 이메일입니다")
                            .build()
            );
        }

        // 2. 기존 인증코드가 있다면 삭제
        emailService.deleteVerificationCode(email);

        // 3. 새 인증 발송 (코드 + 링크)
        boolean emailSent = emailService.sendVerificationEmail(email);

        if (emailSent) {
            return ResponseEntity.ok(
                    UserDto.SendEmailVerificationResponse.builder()
                            .success(true)
                            .message("인증 코드가 이메일로 발송되었습니다")
                            .build()
            );
        }

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                UserDto.SendEmailVerificationResponse.builder()
                        .success(false)
                        .message("이메일 발송 한도를 초과했습니다. 잠시 후 다시 시도해주세요")
                        .build()
        );
    }
    
    // 이메일 인증 코드 검증
    public ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(UserDto.VerifyEmailCodeRequest request) {
        String email = request.getEmail();
        String verificationCode = request.getVerificationCode();

        // 1. 인증코드 검증
        boolean isCodeValid = emailService.verifyEmailCode(email, verificationCode);

        if (isCodeValid) {
            // 2. 인증 성공 시 Redis에 인증된 이메일 저장 (TTL 1시간)
            saveVerifiedEmail(email);

            return ResponseEntity.ok(
                    UserDto.VerifyEmailCodeResponse.builder()
                            .success(true)
                            .message("이메일 인증이 완료되었습니다")
                            .build()
            );
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                UserDto.VerifyEmailCodeResponse.builder()
                        .success(false)
                        .message("잘못된 인증코드이거나 만료된 코드입니다")
                        .build()
        );
    }
    
    // Redis에 인증된 이메일 저장 (TTL 1시간)
    private void saveVerifiedEmail(String email) {
        String key = VERIFIED_EMAIL_PREFIX + email;
        redisTemplate.opsForValue().set(key, "verified", 1, TimeUnit.HOURS);
    }
    
    // 인증된 이메일인지 확인
    private boolean isEmailVerified(String email) {
        String key = VERIFIED_EMAIL_PREFIX + email;
        String value = redisTemplate.opsForValue().get(key);
        return "verified".equals(value);
    }
    
    // 인증된 이메일 Redis에서 제거
    private void removeVerifiedEmail(String email) {
        String key = VERIFIED_EMAIL_PREFIX + email;
        redisTemplate.delete(key);
    }
    
    // 토큰 기반 이메일 인증 (HTML 응답용)
    public String verifyEmailByTokenForHtml(String token, Model model) {
        // 1. 토큰 검증 및 인증 처리
        String email = emailService.verifyEmailByTokenAndGetEmail(token);
        
        if (email != null) {
            // 2. 인증 성공 시 Redis에 인증된 이메일 저장 (TTL 1시간)
            saveVerifiedEmail(email);
            
            // 3. 성공 정보를 모델에 추가
            model.addAttribute("success", true);
            model.addAttribute("message", "이메일 인증이 완료되었습니다");
        } else {
            // 4. 실패 정보를 모델에 추가
            model.addAttribute("success", false);
            model.addAttribute("message", "유효하지 않거나 만료된 인증 링크입니다");
        }

        return "email-verification-result";
    }

    // === 비밀번호 재설정 관련 ===

    // 비밀번호 재설정 코드 발송
    public ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(UserDto.SendPasswordResetRequest request) {
        String email = request.getEmail();

        // 1. 가입된 이메일인지 확인
        if (!userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.SendPasswordResetResponse.builder()
                            .success(false)
                            .message("가입되지 않은 이메일입니다")
                            .build()
            );
        }

        // 2. 기존 인증코드가 있다면 삭제
        emailService.deletePasswordResetVerification(email);

        // 3. 비밀번호 재설정 코드 발송
        boolean emailSent = emailService.sendPasswordResetCode(email);

        if (emailSent) {
            return ResponseEntity.ok(
                    UserDto.SendPasswordResetResponse.builder()
                            .success(true)
                            .message("인증 코드가 이메일로 발송되었습니다")
                            .build()
            );
        }

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                UserDto.SendPasswordResetResponse.builder()
                        .success(false)
                        .message("이메일 발송 한도를 초과했습니다. 잠시 후 다시 시도해주세요")
                        .build()
        );
    }

    // 비밀번호 재설정 코드 검증
    public ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(UserDto.VerifyPasswordResetCodeRequest request) {
        String email = request.getEmail();
        String verificationCode = request.getVerificationCode();

        // 1. 인증코드 검증
        boolean isCodeValid = emailService.verifyPasswordResetCode(email, verificationCode);

        if (isCodeValid) {
            return ResponseEntity.ok(
                    UserDto.VerifyPasswordResetCodeResponse.builder()
                            .success(true)
                            .message("인증이 완료되었습니다")
                            .build()
            );
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                UserDto.VerifyPasswordResetCodeResponse.builder()
                        .success(false)
                        .message("잘못된 인증코드이거나 만료된 코드입니다")
                        .build()
        );
    }

    // 비밀번호 변경
    public ResponseEntity<UserDto.ChangePasswordResponse> changePassword(
            UserDto.ChangePasswordRequest request,
            String refreshToken) {
        String email = request.getEmail();
        String newPassword = request.getNewPassword();

        // 1. 인증 완료 여부 확인
        if (!emailService.isPasswordResetVerified(email)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.ChangePasswordResponse.builder()
                            .success(false)
                            .message("인증이 완료되지 않았습니다")
                            .build()
            );
        }

        // 2. 사용자 조회
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.ChangePasswordResponse.builder()
                            .success(false)
                            .message("사용자를 찾을 수 없습니다")
                            .build()
            );
        }

        // 3. 비밀번호 유효성 검증
        String passwordValidationMessage = PasswordValidator.getValidationMessage(newPassword);
        if (passwordValidationMessage != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.ChangePasswordResponse.builder()
                            .success(false)
                            .message(passwordValidationMessage)
                            .build()
            );
        }

        // 4. 기존 비밀번호와 일치하는지 확인
        if (bCryptPasswordEncoder.matches(newPassword.toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.ChangePasswordResponse.builder()
                            .success(false)
                            .message("기존 비밀번호와 일치합니다")
                            .build()
            );
        }

        // 5. 비밀번호 변경
        User updatedUser = user.toBuilder()
                .password(bCryptPasswordEncoder.encode(newPassword.toLowerCase()))
                .build();
        userRepository.save(updatedUser);

        // 6. 현재 Refresh Token을 블랙리스트에 추가 (보안 강화: 비밀번호 변경 시 로그아웃)
        if (refreshToken != null && !refreshToken.isEmpty()) {
            blacklistService.addToBlacklist(refreshToken);
        }

        // 7. 인증 정보 삭제
        emailService.deletePasswordResetVerification(email);

        return ResponseEntity.ok(
                UserDto.ChangePasswordResponse.builder()
                        .success(true)
                        .message("비밀번호가 변경되었습니다")
                        .build()
        );
    }

    // === 토큰 재발급 ===

    /**
     * Refresh Token으로 새로운 Access Token 발급
     * @param refreshToken Refresh Token (쿠키에서 추출)
     * @return 새로운 Access Token
     */
    public ResponseEntity<UserDto.RefreshTokenResponse> refreshAccessToken(String refreshToken) {
        // 1. Refresh Token이 없는 경우
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.RefreshTokenResponse.builder()
                            .success(false)
                            .message("Refresh Token이 없습니다")
                            .build()
            );
        }

        // 2. 블랙리스트 확인 (로그아웃된 토큰)
        if (blacklistService.isBlacklisted(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.RefreshTokenResponse.builder()
                            .success(false)
                            .message("로그아웃된 토큰입니다")
                            .build()
            );
        }

        // 3. Refresh Token 유효성 검증
        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.RefreshTokenResponse.builder()
                            .success(false)
                            .message("유효하지 않거나 만료된 Refresh Token입니다")
                            .build()
            );
        }

        // 4. Refresh Token에서 userId 추출
        Long userId;
        try {
            userId = jwtUtil.getUserIdFromRefreshToken(refreshToken);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.RefreshTokenResponse.builder()
                            .success(false)
                            .message("토큰 파싱에 실패했습니다")
                            .build()
            );
        }

        // 5. 사용자 존재 확인
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.RefreshTokenResponse.builder()
                            .success(false)
                            .message("사용자를 찾을 수 없습니다")
                            .build()
            );
        }

        // 6. 새로운 Access Token 발급 (Refresh Token은 재사용)
        String[] tokens = jwtUtil.generateTokens(user);
        String newAccessToken = tokens[0];

        // 7. 세션 last_used_at 업데이트 (비동기)
        sessionService.updateLastUsedAt(refreshToken);

        return ResponseEntity.ok(
                UserDto.RefreshTokenResponse.builder()
                        .success(true)
                        .message("토큰이 재발급되었습니다")
                        .token(newAccessToken)
                        .accessTokenExpiresIn(jwtUtil.getAccessTokenExpiresIn())
                        .build()
        );
    }

    // === 로그아웃 ===

    /**
     * 로그아웃 (Refresh Token을 블랙리스트에 추가)
     * @param refreshToken Refresh Token (쿠키에서 추출)
     * @return 로그아웃 결과
     */
    public ResponseEntity<UserDto.LogoutResponse> logout(String refreshToken) {
        // 1. Refresh Token이 있는 경우에만 블랙리스트에 추가
        if (refreshToken != null && !refreshToken.isEmpty()) {
            // 세션 삭제
            sessionService.deleteSessionByToken(refreshToken);
            // 블랙리스트 추가
            blacklistService.addToBlacklist(refreshToken);
        }

        // 2. 쿠키 삭제 (클라이언트에서 처리)
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)  // TODO 배포환경에서는 true로 변경
                .path("/")
                .maxAge(0)  // 즉시 삭제
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
                .body(UserDto.LogoutResponse.builder()
                        .success(true)
                        .message("로그아웃되었습니다")
                        .build()
                );
    }

    // === 세션 관리 ===

    /**
     * Refresh Token에서 사용자 ID 추출
     * @param refreshToken Refresh Token
     * @return 사용자 ID
     */
    public Long getUserIdFromRefreshToken(String refreshToken) {
        return jwtUtil.getUserIdFromRefreshToken(refreshToken);
    }

    /**
     * 사용자 ID로 사용자 정보 조회
     * @param userId 사용자 ID
     * @return 사용자 정보
     */
    public User getUserById(Long userId) {
        return userRepository.findById(userId).orElse(null);
    }

    /**
     * 사용자의 모든 세션 조회
     * @param userId 사용자 ID
     * @return 세션 목록
     */
    public ResponseEntity<UserDto.GetSessionsResponse> getSessions(Long userId) {
        List<RefreshTokenSession> sessions = sessionService.getUserSessions(userId);

        List<UserDto.SessionInfo> sessionInfoList = sessions.stream()
                .map(session -> UserDto.SessionInfo.builder()
                        .sessionId(session.getSessionId().toString())
                        .deviceName(session.getDeviceName())
                        .country(session.getCountry())
                        .lastUsedAt(session.getLastUsedAt().toString())
                        .build())
                .collect(Collectors.toList());

        return ResponseEntity.ok(UserDto.GetSessionsResponse.builder()
                .success(true)
                .message("세션 조회 성공")
                .sessions(sessionInfoList)
                .build());
    }

    /**
     * 특정 세션 삭제
     * @param userId 사용자 ID
     * @param sessionId 세션 ID
     * @return 삭제 결과
     */
    public ResponseEntity<UserDto.DeleteSessionResponse> deleteSession(Long userId, UUID sessionId) {
        // 세션 조회 및 권한 확인
        RefreshTokenSession session = sessionService.getUserSessions(userId).stream()
                .filter(s -> s.getSessionId().equals(sessionId))
                .findFirst()
                .orElse(null);

        if (session == null) {
            return ResponseEntity.badRequest()
                    .body(UserDto.DeleteSessionResponse.builder()
                            .success(false)
                            .message("세션을 찾을 수 없습니다")
                            .build());
        }

        // 세션 삭제
        sessionService.deleteSession(sessionId);

        return ResponseEntity.ok(UserDto.DeleteSessionResponse.builder()
                .success(true)
                .message("세션이 삭제되었습니다")
                .build());
    }

    /**
     * 모든 세션 삭제 (전체 로그아웃)
     * @param userId 사용자 ID
     * @return 삭제 결과
     */
    public ResponseEntity<UserDto.DeleteAllSessionsResponse> deleteAllSessions(
            Long userId
    ) {
        // userId로 모든 세션 조회 후 삭제 및 블랙리스트 추가
        int deletedCount = sessionService.deleteAllUserSessions(userId);

        return ResponseEntity.ok(UserDto.DeleteAllSessionsResponse.builder()
                .success(true)
                .message("모든 세션이 삭제되었습니다")
                .deletedCount(deletedCount)
                .build());
    }
}
