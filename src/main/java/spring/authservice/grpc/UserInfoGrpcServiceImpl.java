package spring.authservice.grpc;

import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import spring.authservice.domain.User;
import spring.authservice.domain.UserRepository;

import java.util.List;
import java.util.Optional;

/**
 * User 정보 조회 gRPC 서비스
 * - team-service 등 다른 서비스에서 User 정보를 빠르게 조회하기 위한 서비스
 * - 권한 체크는 하지 않음 (Gateway에서 JWT 검증 완료)
 * - 단순 User 데이터 조회만 제공
 */
@Slf4j
@GrpcService
@RequiredArgsConstructor
public class UserInfoGrpcServiceImpl extends UserInfoServiceGrpc.UserInfoServiceImplBase {

    private final UserRepository userRepository;

    /**
     * 단일 사용자 닉네임 조회
     */
    @Override
    public void getUserNickname(UserIdRequest request, StreamObserver<UserNicknameResponse> responseObserver) {
        try {
            log.debug("gRPC getUserNickname 호출 - userId: {}", request.getUserId());

            Optional<User> userOptional = userRepository.findById(request.getUserId());

            UserNicknameResponse response = userOptional.map(user ->
                    UserNicknameResponse.newBuilder()
                            .setUserId(user.getId())
                            .setNickname(user.getNickname() != null ? user.getNickname() : "")
                            .setExists(true)
                            .build()
            ).orElseGet(() ->
                    UserNicknameResponse.newBuilder()
                            .setUserId(request.getUserId())
                            .setNickname("")
                            .setExists(false)
                            .build()
            );

            responseObserver.onNext(response);
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("getUserNickname 처리 중 오류 - userId: {}", request.getUserId(), e);
            responseObserver.onError(e);
        }
    }

    /**
     * 여러 사용자 닉네임 일괄 조회
     */
    @Override
    public void getUserNicknames(UserIdsRequest request, StreamObserver<UserNicknamesResponse> responseObserver) {
        try {
            log.debug("gRPC getUserNicknames 호출 - 요청 수: {}", request.getUserIdsList().size());

            List<Long> userIds = request.getUserIdsList();
            List<User> users = userRepository.findAllById(userIds);

            UserNicknamesResponse.Builder responseBuilder = UserNicknamesResponse.newBuilder();

            List<Long> foundUserIds = users.stream().map(User::getId).toList();

            // 조회된 사용자들에 대한 닉네임 설정
            for (User user : users) {
                UserNicknameResponse userNickname = UserNicknameResponse.newBuilder()
                        .setUserId(user.getId())
                        .setNickname(user.getNickname() != null ? user.getNickname() : "")
                        .setExists(true)
                        .build();
                responseBuilder.addUsers(userNickname);
            }

            // 조회되지 않은 사용자들을 exists=false로 응답에 포함
            for (Long requestedUserId : userIds) {
                if (!foundUserIds.contains(requestedUserId)) {
                    UserNicknameResponse notFoundUser = UserNicknameResponse.newBuilder()
                            .setUserId(requestedUserId)
                            .setNickname("")
                            .setExists(false)
                            .build();
                    responseBuilder.addUsers(notFoundUser);
                }
            }

            responseObserver.onNext(responseBuilder.build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("getUserNicknames 처리 중 오류", e);
            responseObserver.onError(e);
        }
    }

    /**
     * 사용자별 최대 워크스페이스 수 조회
     */
    @Override
    public void getUserMaxWorkspaces(UserIdRequest request, StreamObserver<UserMaxWorkspacesResponse> responseObserver) {
        try {
            log.debug("gRPC getUserMaxWorkspaces 호출 - userId: {}", request.getUserId());

            Optional<User> userOptional = userRepository.findById(request.getUserId());

            UserMaxWorkspacesResponse response = userOptional.map(user ->
                    UserMaxWorkspacesResponse.newBuilder()
                            .setUserId(user.getId())
                            .setMaxWorkspaces(user.getMaxWorkspaces())
                            .setExists(true)
                            .build()
            ).orElseGet(() ->
                    UserMaxWorkspacesResponse.newBuilder()
                            .setUserId(request.getUserId())
                            .setMaxWorkspaces(0)
                            .setExists(false)
                            .build()
            );

            responseObserver.onNext(response);
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("getUserMaxWorkspaces 처리 중 오류 - userId: {}", request.getUserId(), e);
            responseObserver.onError(e);
        }
    }

    /**
     * 사용자 닉네임 + 프로필 이미지 조회
     */
    @Override
    public void getUserDisplayInfo(UserIdRequest request, StreamObserver<UserDisplayInfoResponse> responseObserver) {
        try {
            log.debug("gRPC getUserDisplayInfo 호출 - userId: {}", request.getUserId());

            Optional<User> userOptional = userRepository.findById(request.getUserId());

            UserDisplayInfoResponse response = userOptional.map(user ->
                    UserDisplayInfoResponse.newBuilder()
                            .setUserId(user.getId())
                            .setNickname(user.getNickname() != null ? user.getNickname() : "")
                            .setProfileImageUrl(user.getProfileImageUrl() != null ? user.getProfileImageUrl() : "")
                            .setExists(true)
                            .build()
            ).orElseGet(() ->
                    UserDisplayInfoResponse.newBuilder()
                            .setUserId(request.getUserId())
                            .setNickname("")
                            .setProfileImageUrl("")
                            .setExists(false)
                            .build()
            );

            responseObserver.onNext(response);
            responseObserver.onCompleted();

        } catch (Exception e) {
            log.error("getUserDisplayInfo 처리 중 오류 - userId: {}", request.getUserId(), e);
            responseObserver.onError(e);
        }
    }
}
