package spring.authservice.grpc;

import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import org.junit.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.domain.AuthProviderEnum;
import spring.authservice.domain.User;
import spring.authservice.domain.UserRepository;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserInfoGrpcServiceImplTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    @Mock
    private UserRepository userRepository;

    private UserInfoServiceGrpc.UserInfoServiceBlockingStub serviceStub;

    @BeforeEach
    void setUp() throws Exception {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder
                .forName(serverName)
                .directExecutor()
                .addService(new UserInfoGrpcServiceImpl(userRepository))
                .build()
                .start());

        serviceStub = UserInfoServiceGrpc.newBlockingStub(
                grpcCleanup.register(InProcessChannelBuilder
                        .forName(serverName)
                        .directExecutor()
                        .build()));
    }

    @Test
    @DisplayName("단일 사용자 닉네임 조회 - 성공")
    void getUserNickname_success() {
        // given
        User user = User.builder()
                .id(1L)
                .nickname("테스트유저")
                .userId("testuser")
                .email("test@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(1L)
                .build();

        UserNicknameResponse response = serviceStub.getUserNickname(request);

        // then
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getNickname()).isEqualTo("테스트유저");
        assertThat(response.getExists()).isTrue();
    }

    @Test
    @DisplayName("단일 사용자 닉네임 조회 - 사용자 없음")
    void getUserNickname_notFound() {
        // given
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(999L)
                .build();

        UserNicknameResponse response = serviceStub.getUserNickname(request);

        // then
        assertThat(response.getUserId()).isEqualTo(999L);
        assertThat(response.getNickname()).isEmpty();
        assertThat(response.getExists()).isFalse();
    }

    @Test
    @DisplayName("여러 사용자 닉네임 일괄 조회 - 성공")
    void getUserNicknames_success() {
        // given
        User user1 = User.builder()
                .id(1L)
                .nickname("유저1")
                .userId("user1")
                .email("user1@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .build();

        User user2 = User.builder()
                .id(2L)
                .nickname("유저2")
                .userId("user2")
                .email("user2@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .build();

        when(userRepository.findAllById(anyList())).thenReturn(List.of(user1, user2));

        // when
        UserIdsRequest request = UserIdsRequest.newBuilder()
                .addAllUserIds(List.of(1L, 2L, 3L))  // 3L은 없는 사용자
                .build();

        UserNicknamesResponse response = serviceStub.getUserNicknames(request);

        // then
        assertThat(response.getUsersList()).hasSize(3);

        // 존재하는 사용자 확인
        UserNicknameResponse found1 = response.getUsersList().stream()
                .filter(u -> u.getUserId() == 1L)
                .findFirst()
                .orElseThrow();
        assertThat(found1.getNickname()).isEqualTo("유저1");
        assertThat(found1.getExists()).isTrue();

        // 존재하지 않는 사용자 확인
        UserNicknameResponse notFound = response.getUsersList().stream()
                .filter(u -> u.getUserId() == 3L)
                .findFirst()
                .orElseThrow();
        assertThat(notFound.getNickname()).isEmpty();
        assertThat(notFound.getExists()).isFalse();
    }

    @Test
    @DisplayName("사용자 최대 워크스페이스 수 조회 - 성공")
    void getUserMaxWorkspaces_success() {
        // given
        User user = User.builder()
                .id(1L)
                .nickname("테스트유저")
                .userId("testuser")
                .email("test@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .maxWorkspaces(5)
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(1L)
                .build();

        UserMaxWorkspacesResponse response = serviceStub.getUserMaxWorkspaces(request);

        // then
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getMaxWorkspaces()).isEqualTo(5);
        assertThat(response.getExists()).isTrue();
    }

    @Test
    @DisplayName("사용자 최대 워크스페이스 수 조회 - 사용자 없음")
    void getUserMaxWorkspaces_notFound() {
        // given
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(999L)
                .build();

        UserMaxWorkspacesResponse response = serviceStub.getUserMaxWorkspaces(request);

        // then
        assertThat(response.getUserId()).isEqualTo(999L);
        assertThat(response.getMaxWorkspaces()).isEqualTo(0);
        assertThat(response.getExists()).isFalse();
    }

    @Test
    @DisplayName("사용자 디스플레이 정보 조회 - 성공")
    void getUserDisplayInfo_success() {
        // given
        User user = User.builder()
                .id(1L)
                .nickname("테스트유저")
                .userId("testuser")
                .email("test@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .profileImageUrl("https://example.com/profile.jpg")
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(1L)
                .build();

        UserDisplayInfoResponse response = serviceStub.getUserDisplayInfo(request);

        // then
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getNickname()).isEqualTo("테스트유저");
        assertThat(response.getProfileImageUrl()).isEqualTo("https://example.com/profile.jpg");
        assertThat(response.getExists()).isTrue();
    }

    @Test
    @DisplayName("사용자 디스플레이 정보 조회 - 프로필 이미지 없음")
    void getUserDisplayInfo_noProfileImage() {
        // given
        User user = User.builder()
                .id(1L)
                .nickname("테스트유저")
                .userId("testuser")
                .email("test@example.com")
                .password("password")
                .authProvider(AuthProviderEnum.EMAIL)
                .profileImageUrl(null)
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(1L)
                .build();

        UserDisplayInfoResponse response = serviceStub.getUserDisplayInfo(request);

        // then
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getNickname()).isEqualTo("테스트유저");
        assertThat(response.getProfileImageUrl()).isEmpty();
        assertThat(response.getExists()).isTrue();
    }

    @Test
    @DisplayName("사용자 디스플레이 정보 조회 - 사용자 없음")
    void getUserDisplayInfo_notFound() {
        // given
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // when
        UserIdRequest request = UserIdRequest.newBuilder()
                .setUserId(999L)
                .build();

        UserDisplayInfoResponse response = serviceStub.getUserDisplayInfo(request);

        // then
        assertThat(response.getUserId()).isEqualTo(999L);
        assertThat(response.getNickname()).isEmpty();
        assertThat(response.getProfileImageUrl()).isEmpty();
        assertThat(response.getExists()).isFalse();
    }
}
