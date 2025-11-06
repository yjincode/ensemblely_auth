package spring.authservice.application.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import spring.authservice.application.port.in.*;
import spring.authservice.application.port.out.EmailPort;
import spring.authservice.application.service.EmailService.RateLimitResult;
import spring.authservice.application.port.out.TokenCachePort;
import spring.authservice.application.port.out.UserPersistencePort;
import spring.authservice.domain.model.AuthProviderEnum;
import spring.authservice.domain.model.RefreshTokenSession;
import spring.authservice.domain.model.User;
import spring.authservice.domain.vo.KakaoUserInfo;
import spring.authservice.domain.vo.NaverUserInfo;
import spring.authservice.domain.vo.UserDto;
import spring.authservice.util.JwtUtil;
import spring.authservice.util.PasswordValidator;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserService implements
        RegisterUserUseCase,
        AuthenticateUserUseCase,
        ManageTokenUseCase,
        ManageSessionUseCase,
        ResetPasswordUseCase,
        QueryUserInfoUseCase,
        SocialLoginUseCase,
        MergeSocialAccountUseCase {

    // Outbound Ports
    private final UserPersistencePort userPersistencePort;
    private final TokenCachePort tokenCachePort;
    private final EmailPort emailPort;

    // Services
    private final RefreshTokenSessionService sessionService;
    private final NaverOAuthService naverOAuthService;
    private final KakaoOAuthService kakaoOAuthService;

    // Utilities
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;

    private static final String VERIFIED_EMAIL_PREFIX = "verified:";

    @Override
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

        // 2. 비밀번호 유효성 검증
        String passwordValidationMessage = PasswordValidator.getValidationMessage(request.getPassword());
        if (passwordValidationMessage != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.LocalJoinResponse.builder()
                            .success(false)
                            .message(passwordValidationMessage)
                            .build()
            );
        }

        // 3. 사용자 생성 및 저장
        User user = request.toUser(bCryptPasswordEncoder);
        User savedUser = userPersistencePort.save(user);

        // 4. 인증된 이메일 정보 삭제
        removeVerifiedEmail(request.getEmail());

        // 5. 토큰 생성 (자동 로그인)
        String[] tokens = jwtUtil.generateTokens(savedUser);
        String accessToken = tokens[0];
        String refreshToken = tokens[1];

        // 6. 세션 저장
        sessionService.createSession(savedUser.getId(), refreshToken, httpRequest);

        // 7. 리프레시 토큰을 HttpOnly 쿠키로 설정
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
                        .accessToken(accessToken)
                        .build()
                );
    }
    // === AuthenticateUserUseCase 구현 ===

    @Override
    public ResponseEntity<UserDto.LoginResponse> authenticateUser(
            UserDto.LoginRequest request,
            HttpServletRequest httpRequest) {
        // 1. 사용자 조회
        User user = userPersistencePort.findByEmail(request.getEmail())
                .orElse(null);

        // 2. 사용자가 없거나 비밀번호가 틀린 경우 (보안: User Enumeration 방지)
        if (user == null || !bCryptPasswordEncoder.matches(request.getPassword().toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.LoginResponse.builder()
                            .success(false)
                            .message("이메일 또는 비밀번호가 일치하지 않습니다")
                            .build()
            );
        }

        // 3. JWT 토큰 생성
        String[] tokens = jwtUtil.generateTokens(user);
        String accessToken = tokens[0];
        String refreshToken = tokens[1];
        System.out.println("accessToken: " + accessToken);
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
                        .accessToken(accessToken)
                        .build()
                );
    }

    @Override
    public ResponseEntity<UserDto.SendEmailVerificationResponse> sendEmailVerification(UserDto.SendEmailVerificationRequest request) {
        String email = request.getEmail();

        // 1. EMAIL provider로 이미 가입된 이메일인지 체크 (소셜 로그인 이메일은 허용)
        if (userPersistencePort.existsByEmailAndAuthProvider(email, AuthProviderEnum.EMAIL)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    UserDto.SendEmailVerificationResponse.builder()
                            .success(false)
                            .message("이미 가입된 이메일입니다")
                            .build()
            );
        }

        if (isEmailVerified(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.SendEmailVerificationResponse.builder()
                            .success(false)
                            .message("이미 인증 완료된 이메일입니다")
                            .build()
            );
        }

        // 2. 새 인증 발송 (코드 + 링크)
        RateLimitResult result = emailPort.sendVerificationEmail(email);

        // 3. Rate Limit 체크
        switch (result) {
            case ALLOWED:
                return ResponseEntity.ok(
                        UserDto.SendEmailVerificationResponse.builder()
                                .success(true)
                                .message("인증 코드가 이메일로 발송되었습니다")
                                .build()
                );
            case MINUTE_LIMIT:
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                        UserDto.SendEmailVerificationResponse.builder()
                                .success(false)
                                .message("이미 처리되었습니다. 기존에 발송된 이메일을 확인해주세요")
                                .build()
                );
            case DAILY_LIMIT:
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                        UserDto.SendEmailVerificationResponse.builder()
                                .success(false)
                                .message("일일 발송 한도를 초과했습니다. 내일 다시 시도해주세요")
                                .build()
                );
            default:
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                        UserDto.SendEmailVerificationResponse.builder()
                                .success(false)
                                .message("이메일 발송 중 오류가 발생했습니다")
                                .build()
                );
        }
    }

    @Override
    public ResponseEntity<UserDto.VerifyEmailCodeResponse> verifyEmailCode(UserDto.VerifyEmailCodeRequest request) {
        String email = request.getEmail();
        String verificationCode = request.getVerificationCode();

        // 1. 인증코드 검증
        boolean isCodeValid = emailPort.verifyEmailCode(email, verificationCode);

        if (isCodeValid) {
            // 2. 인증 성공 시 Redis에 인증된 이메일 저장 (TTL 1시간)
            saveVerifiedEmail(email);

            // 3. SSE로 프론트엔드에 실시간 알림 (Redis Pub/Sub)
            redisTemplate.convertAndSend("email_verified:" + email, "VERIFIED");

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

    @Override
    public String verifyEmailByTokenForHtml(String token, Model model) {
        // 1. 토큰 검증 및 인증 처리
        String email = emailPort.verifyEmailByTokenAndGetEmail(token);

        if (email != null) {
            // 2. 인증 성공 시 Redis에 인증된 이메일 저장 (TTL 1시간)
            saveVerifiedEmail(email);

            // 3. SSE로 프론트엔드에 실시간 알림 (Redis Pub/Sub)
            redisTemplate.convertAndSend("email_verified:" + email, "VERIFIED");

            // 4. 성공 정보를 모델에 추가
            model.addAttribute("success", true);
            model.addAttribute("message", "이메일 인증이 완료되었습니다");
        } else {
            // 5. 실패 정보를 모델에 추가
            model.addAttribute("success", false);
            model.addAttribute("message", "유효하지 않거나 만료된 인증 링크입니다");
        }

        return "email-verification-result";
    }

    // === ResetPasswordUseCase 구현 ===

    @Override
    public ResponseEntity<UserDto.SendPasswordResetResponse> sendPasswordResetCode(UserDto.SendPasswordResetRequest request) {
        String email = request.getEmail();

        // 1. EMAIL provider로 가입된 이메일인지 확인 (소셜 로그인은 비밀번호 재설정 불가)
        if (!userPersistencePort.existsByEmailAndAuthProvider(email, AuthProviderEnum.EMAIL)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.SendPasswordResetResponse.builder()
                            .success(false)
                            .message("가입되지 않은 이메일입니다")
                            .build()
            );
        }

        // 2. 기존 인증코드가 있다면 삭제
        emailPort.deletePasswordResetVerification(email);

        // 3. 비밀번호 재설정 코드 발송
        RateLimitResult result = emailPort.sendPasswordResetCode(email);

        // 4. Rate Limit 체크
        switch (result) {
            case ALLOWED:
                return ResponseEntity.ok(
                        UserDto.SendPasswordResetResponse.builder()
                                .success(true)
                                .message("인증 코드가 이메일로 발송되었습니다")
                                .build()
                );
            case MINUTE_LIMIT:
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                        UserDto.SendPasswordResetResponse.builder()
                                .success(false)
                                .message("이미 처리되었습니다. 기존에 발송된 이메일을 확인해주세요")
                                .build()
                );
            case DAILY_LIMIT:
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                        UserDto.SendPasswordResetResponse.builder()
                                .success(false)
                                .message("일일 발송 한도를 초과했습니다. 내일 다시 시도해주세요")
                                .build()
                );
            default:
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                        UserDto.SendPasswordResetResponse.builder()
                                .success(false)
                                .message("이메일 발송 중 오류가 발생했습니다")
                                .build()
                );
        }
    }

    @Override
    public ResponseEntity<UserDto.VerifyPasswordResetCodeResponse> verifyPasswordResetCode(UserDto.VerifyPasswordResetCodeRequest request) {
        String email = request.getEmail();
        String verificationCode = request.getVerificationCode();

        // 1. 인증코드 검증
        boolean isCodeValid = emailPort.verifyPasswordResetCode(email, verificationCode);

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

    @Override
    public ResponseEntity<UserDto.ResetPasswordResponse> resetPassword(
            UserDto.ResetPasswordRequest request) {
        String email = request.getEmail();
        String newPassword = request.getNewPassword();

        // 1. 인증 완료 여부 확인
        if (!emailPort.isPasswordResetVerified(email)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.ResetPasswordResponse.builder()
                            .success(false)
                            .message("인증이 완료되지 않았습니다")
                            .build()
            );
        }

        // 2. EMAIL provider 사용자 조회
        User user = userPersistencePort.findByEmailAndAuthProvider(email, AuthProviderEnum.EMAIL).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.ResetPasswordResponse.builder()
                            .success(false)
                            .message("사용자를 찾을 수 없습니다")
                            .build()
            );
        }

        // 3. 비밀번호 유효성 검증
        String passwordValidationMessage = PasswordValidator.getValidationMessage(newPassword);
        if (passwordValidationMessage != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.ResetPasswordResponse.builder()
                            .success(false)
                            .message(passwordValidationMessage)
                            .build()
            );
        }

        // 4. 기존 비밀번호와 일치하는지 확인
        if (bCryptPasswordEncoder.matches(newPassword.toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.ResetPasswordResponse.builder()
                            .success(false)
                            .message("기존 비밀번호와 일치합니다")
                            .build()
            );
        }

        // 5. 비밀번호 변경
        User updatedUser = user.toBuilder()
                .password(bCryptPasswordEncoder.encode(newPassword.toLowerCase()))
                .build();
        userPersistencePort.save(updatedUser);

        // 6. 모든 세션 삭제 (보안 강화: 비밀번호 재설정 시 전체 로그아웃)
        sessionService.deleteAllUserSessions(user.getId());

        // 7. 인증 정보 삭제
        emailPort.deletePasswordResetVerification(email);

        return ResponseEntity.ok(
                UserDto.ResetPasswordResponse.builder()
                        .success(true)
                        .message("비밀번호가 변경되었습니다")
                        .build()
        );
    }

    // === ManageTokenUseCase 구현 ===

    @Override
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
        if (tokenCachePort.isBlacklisted(refreshToken)) {
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
        User user = userPersistencePort.findById(userId).orElse(null);
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
                        .accessToken(newAccessToken)
                        .accessTokenExpiresIn(jwtUtil.getAccessTokenExpiresIn())
                        .build()
        );
    }

    @Override
    public ResponseEntity<UserDto.LogoutResponse> logout(String refreshToken) {
        // 1. Refresh Token이 있는 경우에만 블랙리스트에 추가
        if (refreshToken != null && !refreshToken.isEmpty()) {
            sessionService.deleteSessionByToken(refreshToken);
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

    // === QueryUserInfoUseCase 구현 ===

    @Override
    public Long getUserIdFromRefreshToken(String refreshToken) {
        return jwtUtil.getUserIdFromRefreshToken(refreshToken);
    }

    @Override
    public User getUserById(Long userId) {
        return userPersistencePort.findById(userId).orElse(null);
    }

    // === ManageSessionUseCase 구현 ===

    @Override
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

    @Override
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

    @Override
    public ResponseEntity<UserDto.DeleteAllSessionsResponse> deleteAllSessions(Long userId) {
        // userId로 모든 세션 조회 후 삭제 및 블랙리스트 추가
        int deletedCount = sessionService.deleteAllUserSessions(userId);

        return ResponseEntity.ok(UserDto.DeleteAllSessionsResponse.builder()
                .success(true)
                .message("모든 세션이 삭제되었습니다")
                .deletedCount(deletedCount)
                .build());
    }

    // === SocialLoginUseCase 구현 ===

    @Override
    public ResponseEntity<UserDto.SocialLoginResponse> socialLogin(
            UserDto.SocialLoginRequest request,
            HttpServletRequest httpRequest) {

        String provider = request.getProvider().toLowerCase();
        String accessToken = request.getAccessToken();

        // 1. Provider별 토큰 검증 및 사용자 정보 조회
        String email;
        String socialId;
        String nickname;

        switch (provider) {
            case "naver":
                NaverUserInfo naverUserInfo = naverOAuthService.verifyToken(accessToken);
                if (naverUserInfo == null || !naverUserInfo.isSuccess()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                            UserDto.SocialLoginResponse.builder()
                                    .success(false)
                                    .message("네이버 토큰 검증에 실패했습니다")
                                    .build()
                    );
                }
                email = naverUserInfo.getResponse().getEmail();
                socialId = naverUserInfo.getResponse().getId();
                nickname = naverUserInfo.getResponse().getNickname();
                break;

            case "kakao":
                KakaoUserInfo kakaoUserInfo = kakaoOAuthService.verifyToken(accessToken);
                if (kakaoUserInfo == null || !kakaoUserInfo.isSuccess()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                            UserDto.SocialLoginResponse.builder()
                                    .success(false)
                                    .message("카카오 토큰 검증에 실패했습니다")
                                    .build()
                    );
                }
                email = kakaoUserInfo.getEmail();
                socialId = kakaoUserInfo.getKakaoId();
                nickname = kakaoUserInfo.getNickname();
                break;

            case "google":
                // TODO: Google OAuth 구현
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(
                        UserDto.SocialLoginResponse.builder()
                                .success(false)
                                .message("구글 로그인은 준비 중입니다")
                                .build()
                );

            default:
                return ResponseEntity.badRequest().body(
                        UserDto.SocialLoginResponse.builder()
                                .success(false)
                                .message("지원하지 않는 로그인 방식입니다")
                                .build()
                );
        }

        // 2. 이메일 검증
        if (email == null || email.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    UserDto.SocialLoginResponse.builder()
                            .success(false)
                            .message("이메일 정보를 가져올 수 없습니다")
                            .build()
            );
        }

        // 3. 사용자 조회 또는 생성
        AuthProviderEnum requestProvider = AuthProviderEnum.valueOf(provider.toUpperCase());
        User user = userPersistencePort.findByEmailAndAuthProvider(email, requestProvider).orElse(null);
        boolean isNewUser = false;

        if (user == null) {
            // 동일 이메일의 EMAIL 계정이 있는지 확인 (통합 필요)
            User emailUser = userPersistencePort.findByEmailAndAuthProvider(email, AuthProviderEnum.EMAIL).orElse(null);
            if (emailUser != null) {
                // 일반 이메일 가입자 → 계정 통합 필요 (409)
                log.info("계정 통합 필요: email={}, 기존provider=EMAIL, 요청provider={}", email, provider);
                return ResponseEntity.status(HttpStatus.CONFLICT).body(
                        UserDto.SocialLoginResponse.builder()
                                .success(false)
                                .message("이미 가입된 이메일입니다")
                                .mergeRequired(true)
                                .email(email)
                                .build()
                );
            }

            // 신규 가입
            user = User.builder()
                    .email(email)
                    .socialId(socialId)
                    .nickname(nickname != null ? nickname : email.split("@")[0])
                    .username(email.split("@")[0])
                    .password(bCryptPasswordEncoder.encode(UUID.randomUUID().toString())) // 소셜 로그인은 비밀번호 사용 안함
                    .authProvider(requestProvider)
                    .build();

            user = userPersistencePort.save(user);
            isNewUser = true;
            log.info("신규 소셜 회원가입: email={}, provider={}", email, provider);
        } else {
            // 기존 사용자 존재 - 같은 provider로 이미 가입됨 → 로그인 처리
            log.info("기존 소셜 사용자 로그인: email={}, provider={}", email, provider);
        }

        // 4. JWT 토큰 생성
        String[] tokens = jwtUtil.generateTokens(user);
        String jwtAccessToken = tokens[0];
        String refreshToken = tokens[1];

        // 5. 세션 저장
        sessionService.createSession(user.getId(), refreshToken, httpRequest);

        // 6. 리프레시 토큰을 HttpOnly 쿠키로 설정
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)  // TODO 배포환경에서는 true로 변경
                .path("/")
                .maxAge(30 * 24 * 60 * 60)  // 30일
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(UserDto.SocialLoginResponse.builder()
                        .success(true)
                        .message(isNewUser ? "회원가입이 완료되었습니다" : "로그인이 완료되었습니다")
                        .accessToken(jwtAccessToken)
                        .isNewUser(isNewUser)
                        .build()
                );
    }

    // === MergeSocialAccountUseCase 구현 ===

    @Override
    public ResponseEntity<UserDto.SocialMergeResponse> mergeSocialAccount(
            UserDto.SocialMergeRequest request,
            HttpServletRequest httpRequest) {

        String email = request.getEmail();
        String password = request.getPassword();
        String provider = request.getProvider().toLowerCase();
        String accessToken = request.getAccessToken();

        // 1. EMAIL 계정 조회 (이메일 가입자만 통합 가능)
        User user = userPersistencePort.findByEmailAndAuthProvider(email, AuthProviderEnum.EMAIL).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    UserDto.SocialMergeResponse.builder()
                            .success(false)
                            .message("이메일 가입 계정을 찾을 수 없습니다")
                            .build()
            );
        }

        // 2. 비밀번호 확인 (본인 인증)
        if (!bCryptPasswordEncoder.matches(password.toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    UserDto.SocialMergeResponse.builder()
                            .success(false)
                            .message("비밀번호가 일치하지 않습니다")
                            .build()
            );
        }

        // 3. Provider별 소셜 토큰 검증 및 사용자 정보 조회
        String socialId;
        switch (provider) {
            case "naver":
                NaverUserInfo naverUserInfo = naverOAuthService.verifyToken(accessToken);
                if (naverUserInfo == null || !naverUserInfo.isSuccess()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                            UserDto.SocialMergeResponse.builder()
                                    .success(false)
                                    .message("네이버 토큰 검증에 실패했습니다")
                                    .build()
                    );
                }
                // 이메일 일치 확인
                if (!email.equals(naverUserInfo.getResponse().getEmail())) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                            UserDto.SocialMergeResponse.builder()
                                    .success(false)
                                    .message("소셜 계정의 이메일이 일치하지 않습니다")
                                    .build()
                    );
                }
                socialId = naverUserInfo.getResponse().getId();
                break;

            case "kakao":
                KakaoUserInfo kakaoMergeInfo = kakaoOAuthService.verifyToken(accessToken);
                if (kakaoMergeInfo == null || !kakaoMergeInfo.isSuccess()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                            UserDto.SocialMergeResponse.builder()
                                    .success(false)
                                    .message("카카오 토큰 검증에 실패했습니다")
                                    .build()
                    );
                }
                // 이메일 일치 확인
                if (!email.equals(kakaoMergeInfo.getEmail())) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                            UserDto.SocialMergeResponse.builder()
                                    .success(false)
                                    .message("소셜 계정의 이메일이 일치하지 않습니다")
                                    .build()
                    );
                }
                socialId = kakaoMergeInfo.getKakaoId();
                break;

            case "google":
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(
                        UserDto.SocialMergeResponse.builder()
                                .success(false)
                                .message("구글 로그인은 준비 중입니다")
                                .build()
                );

            default:
                return ResponseEntity.badRequest().body(
                        UserDto.SocialMergeResponse.builder()
                                .success(false)
                                .message("지원하지 않는 로그인 방식입니다")
                                .build()
                );
        }

        // 4. 계정 통합: authProvider 및 socialId 업데이트
        User updatedUser = user.toBuilder()
                .authProvider(AuthProviderEnum.valueOf(provider.toUpperCase()))
                .socialId(socialId)
                .build();
        userPersistencePort.save(updatedUser);

        log.info("소셜 계정 통합 완료: email={}, provider={}", email, provider);

        // 5. JWT 토큰 생성
        String[] tokens = jwtUtil.generateTokens(updatedUser);
        String jwtAccessToken = tokens[0];
        String refreshToken = tokens[1];

        // 6. 세션 저장
        sessionService.createSession(updatedUser.getId(), refreshToken, httpRequest);

        // 7. 리프레시 토큰을 HttpOnly 쿠키로 설정
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)  // TODO 배포환경에서는 true로 변경
                .path("/")
                .maxAge(30 * 24 * 60 * 60)  // 30일
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(UserDto.SocialMergeResponse.builder()
                        .success(true)
                        .message("소셜 계정 통합이 완료되었습니다")
                        .accessToken(jwtAccessToken)
                        .build()
                );
    }

    /**
     * Provider 표시 이름 반환
     */
    private String getProviderDisplayName(AuthProviderEnum provider) {
        switch (provider) {
            case NAVER:
                return "네이버";
            case KAKAO:
                return "카카오";
            case GOOGLE:
                return "구글";
            case EMAIL:
                return "이메일";
            default:
                return provider.name();
        }
    }
}