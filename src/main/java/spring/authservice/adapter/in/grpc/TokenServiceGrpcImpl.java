package spring.authservice.adapter.in.grpc;

import io.grpc.stub.StreamObserver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import org.springframework.http.ResponseEntity;
import spring.authservice.application.service.RefreshTokenBlacklistService;
import spring.authservice.application.service.RefreshTokenSessionService;
import spring.authservice.application.port.in.ManageTokenUseCase;
import spring.authservice.application.port.in.QueryUserInfoUseCase;
import spring.authservice.domain.vo.UserDto;
import spring.authservice.util.JwtUtil;
import spring.authservice.grpc.TokenServiceGrpc;
import spring.authservice.grpc.ValidateTokenRequest;
import spring.authservice.grpc.ValidateTokenResponse;
import spring.authservice.grpc.ValidationLevel;
import spring.authservice.grpc.LogoutRequest;
import spring.authservice.grpc.LogoutResponse;

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
    private final ManageTokenUseCase manageTokenUseCase;
    private final QueryUserInfoUseCase queryUserInfoUseCase;
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
            // 1. Access Token 검증 시도
            Long userId = validateAccessToken(accessToken);

            // 2. Access Token 실패 시 Refresh Token으로 재발급
            TokenRefreshResult refreshResult = null;
            if (userId == null && !refreshToken.isEmpty()) {
                refreshResult = validateAndRefreshToken(refreshToken, responseObserver);
                if (refreshResult == null) {
                    return; // 이미 에러 응답 전송됨
                }
                userId = refreshResult.userId;
            }

            // 3. 인증 실패
            if (userId == null) {
                sendErrorResponse(responseObserver, "INVALID");
                return;
            }

            // 4. 성공 응답 생성
            sendSuccessResponse(responseObserver, userId, level, refreshResult);

        } catch (ExpiredJwtException e) {
            sendErrorResponse(responseObserver, "EXPIRED");
        } catch (MalformedJwtException e) {
            sendErrorResponse(responseObserver, "MALFORMED");
        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage(), e);
            sendErrorResponse(responseObserver, "INVALID");
        }
    }

    /**
     * Access Token 검증
     * @return userId (실패 시 null)
     */
    private Long validateAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return null;
        }

        try {
            if (jwtUtil.validateAccessToken(accessToken)) {
                return jwtUtil.getUserIdFromAccessToken(accessToken);
            }
        } catch (ExpiredJwtException e) {
            log.debug("Access Token expired, will try refresh");
        }
        return null;
    }

    /**
     * Refresh Token 검증 및 새 Access Token 발급
     * @return TokenRefreshResult (실패 시 null, 이미 에러 응답 전송됨)
     */
    private TokenRefreshResult validateAndRefreshToken(
            String refreshToken,
            StreamObserver<ValidateTokenResponse> responseObserver) {

        // 블랙리스트 확인
        if (blacklistService.isBlacklisted(refreshToken)) {
            sendErrorResponse(responseObserver, "BLACKLISTED");
            return null;
        }

        // Refresh Token 검증
        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            sendErrorResponse(responseObserver, "INVALID");
            return null;
        }

        // userId 추출 및 사용자 조회
        Long userId = jwtUtil.getUserIdFromRefreshToken(refreshToken);
        spring.authservice.domain.model.User user = queryUserInfoUseCase.getUserById(userId);
        if (user == null) {
            sendErrorResponse(responseObserver, "INVALID");
            return null;
        }

        // 새 Access Token 발급
        String[] tokens = jwtUtil.generateTokens(user);
        String newAccessToken = tokens[0];
        long expiresIn = jwtUtil.getAccessTokenExpiresIn();

        // 세션 업데이트
        sessionService.updateLastUsedAt(refreshToken);

        return new TokenRefreshResult(userId, newAccessToken, expiresIn);
    }

    /**
     * 에러 응답 전송
     */
    private void sendErrorResponse(StreamObserver<ValidateTokenResponse> responseObserver, String errorReason) {
        responseObserver.onNext(ValidateTokenResponse.newBuilder()
                .setValid(false)
                .setErrorReason(errorReason)
                .build());
        responseObserver.onCompleted();
    }

    /**
     * 성공 응답 전송
     */
    private void sendSuccessResponse(
            StreamObserver<ValidateTokenResponse> responseObserver,
            Long userId,
            ValidationLevel level,
            TokenRefreshResult refreshResult) {

        ValidateTokenResponse.Builder responseBuilder = ValidateTokenResponse.newBuilder()
                .setValid(true);

        // ValidationLevel에 따라 userId 포함
        if (level.getNumber() >= ValidationLevel.WITH_USER_ID.getNumber()) {
            responseBuilder.setUserId(userId);
        }

        // 새 Access Token 발급된 경우
        if (refreshResult != null) {
            responseBuilder
                    .setNewAccessToken(refreshResult.newAccessToken)
                    .setAccessTokenExpiresIn(refreshResult.expiresIn);
        }

        responseObserver.onNext(responseBuilder.build());
        responseObserver.onCompleted();
    }

    /**
     * 토큰 재발급 결과
     */
    private static class TokenRefreshResult {
        final Long userId;
        final String newAccessToken;
        final long expiresIn;

        TokenRefreshResult(Long userId, String newAccessToken, long expiresIn) {
            this.userId = userId;
            this.newAccessToken = newAccessToken;
            this.expiresIn = expiresIn;
        }
    }

    /**
     * Access Token 재발급
     */
    @Override
    public void refreshAccessToken(spring.authservice.grpc.RefreshTokenRequest request,
                                    StreamObserver<spring.authservice.grpc.RefreshTokenResponse> responseObserver) {
        try {
            // ManageTokenUseCase 호출
            ResponseEntity<UserDto.RefreshTokenResponse> response =
                    manageTokenUseCase.refreshAccessToken(request.getRefreshToken());
            UserDto.RefreshTokenResponse body = response.getBody();

            if (body != null) {
                responseObserver.onNext(spring.authservice.grpc.RefreshTokenResponse.newBuilder()
                        .setSuccess(body.isSuccess())
                        .setAccessToken(body.getAccessToken() != null ? body.getAccessToken() : "")
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
            // ManageTokenUseCase 호출
            ResponseEntity<UserDto.LogoutResponse> response =
                    manageTokenUseCase.logout(request.getRefreshToken());
            UserDto.LogoutResponse body = response.getBody();

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
