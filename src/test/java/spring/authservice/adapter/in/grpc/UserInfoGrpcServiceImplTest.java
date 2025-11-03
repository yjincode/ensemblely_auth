package spring.authservice.adapter.in.grpc;

import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.adapter.out.persistence.UserRepository;
import spring.authservice.application.port.out.UserPersistencePort;
import spring.authservice.domain.model.User;
import spring.authservice.grpc.UserIdRequest;
import spring.authservice.grpc.UserNicknameResponse;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * UserInfoGrpcServiceImpl 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserInfoGrpcServiceImpl 단위 테스트")
class UserInfoGrpcServiceImplTest {

    @Mock
    private UserPersistencePort userPersistencePort;

    @Mock
    private UserRepository userRepository;

    @Mock
    private StreamObserver<UserNicknameResponse> responseObserver;

    @InjectMocks
    private UserInfoGrpcServiceImpl userInfoGrpcService;

    @Test
    @DisplayName("사용자 닉네임 조회 성공")
    void getUserNickname_Success() {
        // Given
        Long userId = 1L;
        User mockUser = User.builder()
                .id(userId)
                .nickname("테스트유저")
                .email("test@example.com")
                .build();

        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(userId)
                .build();

        when(userPersistencePort.findById(userId)).thenReturn(Optional.of(mockUser));

        // When
        userInfoGrpcService.getUserNickname(request, responseObserver);

        // Then
        verify(responseObserver, times(1)).onNext(any(UserNicknameResponse.class));
        verify(responseObserver, times(1)).onCompleted();
        verify(userPersistencePort, times(1)).findById(userId);
    }

    @Test
    @DisplayName("사용자 닉네임 조회 실패 - 존재하지 않는 사용자")
    void getUserNickname_UserNotFound() {
        // Given
        Long userId = 999L;
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(userId)
                .build();

        when(userPersistencePort.findById(userId)).thenReturn(Optional.empty());

        // When
        userInfoGrpcService.getUserNickname(request, responseObserver);

        // Then
        verify(responseObserver, times(1)).onNext(any(UserNicknameResponse.class));
        verify(responseObserver, times(1)).onCompleted();
        verify(userPersistencePort, times(1)).findById(userId);
    }
}
