package spring.authservice.adapter.in.grpc;

import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.application.port.in.ManageTokenUseCase;
import spring.authservice.application.port.in.QueryUserInfoUseCase;
import spring.authservice.application.service.RefreshTokenBlacklistService;
import spring.authservice.application.service.RefreshTokenSessionService;
import spring.authservice.grpc.ValidateTokenRequest;
import spring.authservice.grpc.ValidateTokenResponse;
import spring.authservice.grpc.ValidationLevel;
import spring.authservice.util.JwtUtil;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * TokenServiceGrpcImpl 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TokenServiceGrpcImpl 단위 테스트")
class TokenServiceGrpcImplTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RefreshTokenBlacklistService blacklistService;

    @Mock
    private ManageTokenUseCase manageTokenUseCase;

    @Mock
    private QueryUserInfoUseCase queryUserInfoUseCase;

    @Mock
    private RefreshTokenSessionService sessionService;

    @Mock
    private StreamObserver<ValidateTokenResponse> responseObserver;

    @InjectMocks
    private TokenServiceGrpcImpl tokenServiceGrpc;

    @Test
    @DisplayName("토큰 검증 - 유효한 Access Token")
    void validateRefreshToken_ValidAccessToken() {
        // Given
        ValidateTokenRequest request = ValidateTokenRequest.newBuilder()
                .setAccessToken("valid-access-token")
                .setRefreshToken("refresh-token")
                .setLevel(ValidationLevel.BASIC)
                .build();

        when(jwtUtil.validateAccessToken("valid-access-token")).thenReturn(true);
        when(jwtUtil.getUserIdFromAccessToken("valid-access-token")).thenReturn(1L);

        // When
        tokenServiceGrpc.validateRefreshToken(request, responseObserver);

        // Then
        verify(responseObserver, times(1)).onNext(any(ValidateTokenResponse.class));
        verify(responseObserver, times(1)).onCompleted();
    }

    @Test
    @DisplayName("토큰 검증 - 블랙리스트에 등록된 Refresh Token")
    void validateRefreshToken_BlacklistedToken() {
        // Given
        ValidateTokenRequest request = ValidateTokenRequest.newBuilder()
                .setAccessToken("")
                .setRefreshToken("blacklisted-token")
                .setLevel(ValidationLevel.BASIC)
                .build();

        when(blacklistService.isBlacklisted("blacklisted-token")).thenReturn(true);

        // When
        tokenServiceGrpc.validateRefreshToken(request, responseObserver);

        // Then
        verify(responseObserver, times(1)).onNext(any(ValidateTokenResponse.class));
        verify(responseObserver, times(1)).onCompleted();
        verify(jwtUtil, never()).validateRefreshToken(anyString());
    }
}
