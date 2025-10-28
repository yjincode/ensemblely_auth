package spring.authservice.grpc;

import io.grpc.stub.StreamObserver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import spring.authservice.service.RefreshTokenBlacklistService;
import spring.authservice.service.RefreshTokenSessionService;
import spring.authservice.service.UserService;
import spring.authservice.util.JwtUtil;

/**
 * Token Service gRPC 구현
 * - 게이트웨이에서 토큰 검증 및 관리
 * - 마이크로서비스 간 내부 통신용
 */
@Slf4j
@GrpcService
@RequiredArgsConstructor
public class TokenServiceGrpcImpl extends TokenServiceGrpc.TokenServiceImplBase {

    private final JwtUtil jwtUtil;
    private final RefreshTokenBlacklistService blacklistService;
    private final UserService userService;
    private final RefreshTokenSessionService sessionService;

    /**
     * 토큰 검증 (게이트웨이 필터용)
     * Access Token 우선 검증, 만료시 Refresh Token으로 재발급
     */
    @Override
    public void validateRefreshToken(ValidateTokenRequest request,
                                      StreamObserver<ValidateTokenResponse> responseObserver) {
        String accessToken = request.getAccessToken();
        String refreshToken = request.getRefreshToken();
        ValidationLevel level = request.getLevel();

        try {
            Long userId = null;
            String newAccessToken = null;
            long expiresIn = 0;

            // 1. Access Token 검증 시도
            if (accessToken != null && !accessToken.isEmpty()) {
                try {
                    if (jwtUtil.validateAccessToken(accessToken)) {
                        // Access Token 유효 → userId 추출
                        userId = jwtUtil.getUserIdFromAccessToken(accessToken);
                    }
                } catch (ExpiredJwtException e) {
                    // Access Token 만료 → Refresh Token으로 재발급 시도
                    log.debug("Access Token expired, trying refresh");
                }
            }

            // 2. Access Token이 만료되었거나 없으면 Refresh Token으로 재발급
            if (userId == null && refreshToken != null && !refreshToken.isEmpty()) {
                // 블랙리스트 확인
                if (blacklistService.isBlacklisted(refreshToken)) {
                    responseObserver.onNext(ValidateTokenResponse.newBuilder()
                            .setValid(false)
                            .setErrorReason("BLACKLISTED")
                            .build());
                    responseObserver.onCompleted();
                    return;
                }

                // Refresh Token 검증
                if (!jwtUtil.validateRefreshToken(refreshToken)) {
                    responseObserver.onNext(ValidateTokenResponse.newBuilder()
                            .setValid(false)
                            .setErrorReason("INVALID")
                            .build());
                    responseObserver.onCompleted();
                    return;
                }

                // userId 추출 및 새 Access Token 발급
                userId = jwtUtil.getUserIdFromRefreshToken(refreshToken);
                var user = userService.getUserById(userId);
                if (user == null) {
                    responseObserver.onNext(ValidateTokenResponse.newBuilder()
                            .setValid(false)
                            .setErrorReason("INVALID")
                            .build());
                    responseObserver.onCompleted();
                    return;
                }

                var tokens = jwtUtil.generateTokens(user);
                newAccessToken = tokens[0];
                expiresIn = jwtUtil.getAccessTokenExpiresIn();

                // 세션 last_used_at 업데이트
                sessionService.updateLastUsedAt(refreshToken);
            }

            // 3. 인증 실패
            if (userId == null) {
                responseObserver.onNext(ValidateTokenResponse.newBuilder()
                        .setValid(false)
                        .setErrorReason("INVALID")
                        .build());
                responseObserver.onCompleted();
                return;
            }

            // 4. ValidationLevel에 따라 응답 구성
            ValidateTokenResponse.Builder responseBuilder = ValidateTokenResponse.newBuilder()
                    .setValid(true);

            // BASIC: 인증만
            if (level == ValidationLevel.BASIC) {
                // valid만 반환
            }
            // WITH_USER_ID 이상: userId 포함
            else if (level.getNumber() >= ValidationLevel.WITH_USER_ID.getNumber()) {
                responseBuilder.setUserId(userId);
            }

            // 새 Access Token 발급된 경우
            if (newAccessToken != null) {
                responseBuilder
                        .setNewAccessToken(newAccessToken)
                        .setAccessTokenExpiresIn(expiresIn);
            }

            // WITH_NICKNAME 이상: 사용자 정보 조회
            if (level.getNumber() >= ValidationLevel.WITH_NICKNAME.getNumber()) {
                var user = userService.getUserById(userId);
                if (user != null) {
                    responseBuilder.setNickname(user.getNickname());

                    // WITH_FULL_PROFILE: 프로필 이미지 포함
                    if (level == ValidationLevel.WITH_FULL_PROFILE && user.getProfileImageUrl() != null) {
                        responseBuilder.setProfileImageUrl(user.getProfileImageUrl());
                    }
                }
            }

            responseObserver.onNext(responseBuilder.build());
            responseObserver.onCompleted();

        } catch (ExpiredJwtException e) {
            responseObserver.onNext(ValidateTokenResponse.newBuilder()
                    .setValid(false)
                    .setErrorReason("EXPIRED")
                    .build());
            responseObserver.onCompleted();
        } catch (MalformedJwtException e) {
            responseObserver.onNext(ValidateTokenResponse.newBuilder()
                    .setValid(false)
                    .setErrorReason("MALFORMED")
                    .build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage(), e);
            responseObserver.onNext(ValidateTokenResponse.newBuilder()
                    .setValid(false)
                    .setErrorReason("INVALID")
                    .build());
            responseObserver.onCompleted();
        }
    }

    /**
     * Access Token 재발급
     */
    @Override
    public void refreshAccessToken(spring.authservice.grpc.RefreshTokenRequest request,
                                    StreamObserver<spring.authservice.grpc.RefreshTokenResponse> responseObserver) {
        try {
            // UserService 호출
            var response = userService.refreshAccessToken(request.getRefreshToken());
            var body = response.getBody();

            if (body != null) {
                responseObserver.onNext(spring.authservice.grpc.RefreshTokenResponse.newBuilder()
                        .setSuccess(body.isSuccess())
                        .setAccessToken(body.getToken() != null ? body.getToken() : "")
                        .setAccessTokenExpiresIn(body.getAccessTokenExpiresIn())
                        .setMessage(body.getMessage())
                        .build());
            } else {
                responseObserver.onNext(spring.authservice.grpc.RefreshTokenResponse.newBuilder()
                        .setSuccess(false)
                        .setMessage("토큰 갱신 실패")
                        .build());
            }
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("Token refresh error: {}", e.getMessage(), e);
            responseObserver.onNext(spring.authservice.grpc.RefreshTokenResponse.newBuilder()
                    .setSuccess(false)
                    .setMessage("토큰 갱신 중 오류 발생")
                    .build());
            responseObserver.onCompleted();
        }
    }

    /**
     * 로그아웃 (세션 무효화)
     */
    @Override
    public void logout(LogoutRequest request,
                       StreamObserver<LogoutResponse> responseObserver) {
        try {
            // UserService 호출
            var response = userService.logout(request.getRefreshToken());
            var body = response.getBody();

            if (body != null) {
                responseObserver.onNext(LogoutResponse.newBuilder()
                        .setSuccess(body.isSuccess())
                        .setMessage(body.getMessage())
                        .build());
            } else {
                responseObserver.onNext(LogoutResponse.newBuilder()
                        .setSuccess(false)
                        .setMessage("로그아웃 실패")
                        .build());
            }
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("Logout error: {}", e.getMessage(), e);
            responseObserver.onNext(LogoutResponse.newBuilder()
                    .setSuccess(false)
                    .setMessage("로그아웃 중 오류 발생")
                    .build());
            responseObserver.onCompleted();
        }
    }
}
