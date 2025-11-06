package spring.authservice.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import spring.authservice.application.port.in.UpdateProfileUseCase;
import spring.authservice.application.port.out.FileStoragePort;
import spring.authservice.application.port.out.UserPersistencePort;
import spring.authservice.domain.model.User;
import spring.authservice.domain.vo.UserDto;
import spring.authservice.util.PasswordValidator;

import java.io.IOException;
import java.util.List;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ProfileService implements UpdateProfileUseCase {

    private final FileStoragePort fileStoragePort;
    private final UserPersistencePort userPersistencePort;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
    private static final List<String> ALLOWED_EXTENSIONS = List.of("jpg", "jpeg", "png", "gif", "webp");

    @Override
    public ResponseEntity<UserDto.UploadProfileImageResponse> uploadProfileImage(Long userId, MultipartFile file) {
        log.info("프로필 이미지 업로드 시작 - userId: {}", userId);

        // 1. 파일 검증
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(UserDto.UploadProfileImageResponse.builder()
                            .success(false)
                            .message("파일이 비어있습니다")
                            .build());
        }

        // 2. 파일 확장자 검증
        String filename = file.getOriginalFilename();
        String extension = getFileExtension(filename);
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            return ResponseEntity.badRequest()
                    .body(UserDto.UploadProfileImageResponse.builder()
                            .success(false)
                            .message("허용되지 않는 파일 형식입니다. (허용: jpg, jpeg, png, gif, webp)")
                            .build());
        }

        // 3. 파일 크기 검증 (5MB 제한)
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest()
                    .body(UserDto.UploadProfileImageResponse.builder()
                            .success(false)
                            .message("파일 크기는 5MB 이하여야 합니다")
                            .build());
        }

        try {
            // 4. 사용자 조회
            User user = userPersistencePort.findById(userId).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(UserDto.UploadProfileImageResponse.builder()
                                .success(false)
                                .message("사용자를 찾을 수 없습니다")
                                .build());
            }

            // 5. 기존 프로필 이미지가 있으면 삭제
            if (user.getProfileImageUrl() != null && !user.getProfileImageUrl().isEmpty()) {
                try {
                    fileStoragePort.deleteProfileImage(user.getProfileImageUrl());
                    log.info("기존 프로필 이미지 삭제 - userId: {}", userId);
                } catch (Exception e) {
                    log.warn("기존 프로필 이미지 삭제 실패 - userId: {}, error: {}", userId, e.getMessage());
                }
            }

            // 6. 새 프로필 이미지 업로드
            String imageUrl = fileStoragePort.uploadProfileImage(
                    userId,
                    filename,
                    file.getContentType(),
                    file.getInputStream(),
                    file.getSize()
            );

            // 7. User 엔티티 업데이트
            User updatedUser = user.toBuilder()
                    .profileImageUrl(imageUrl)
                    .build();
            userPersistencePort.save(updatedUser);

            log.info("프로필 이미지 업로드 완료 - userId: {}, imageUrl: {}", userId, imageUrl);
            return ResponseEntity.ok(UserDto.UploadProfileImageResponse.builder()
                    .success(true)
                    .message("프로필 이미지가 업로드되었습니다")
                    .imageUrl(imageUrl)
                    .build());

        } catch (IOException e) {
            log.error("프로필 이미지 업로드 실패 - userId: {}, error: {}", userId, e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(UserDto.UploadProfileImageResponse.builder()
                            .success(false)
                            .message("파일 처리 중 오류가 발생했습니다")
                            .build());
        } catch (Exception e) {
            log.error("프로필 이미지 업로드 실패 - userId: {}, error: {}", userId, e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(UserDto.UploadProfileImageResponse.builder()
                            .success(false)
                            .message(e.getMessage())
                            .build());
        }
    }

    @Override
    public ResponseEntity<UserDto.DeleteProfileImageResponse> deleteProfileImage(Long userId) {
        log.info("프로필 이미지 삭제 시작 - userId: {}", userId);

        // 1. 사용자 조회
        User user = userPersistencePort.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(UserDto.DeleteProfileImageResponse.builder()
                            .success(false)
                            .message("사용자를 찾을 수 없습니다")
                            .build());
        }

        // 2. 프로필 이미지가 없으면 실패
        if (user.getProfileImageUrl() == null || user.getProfileImageUrl().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(UserDto.DeleteProfileImageResponse.builder()
                            .success(false)
                            .message("삭제할 프로필 이미지가 없습니다")
                            .build());
        }

        try {
            // 3. S3에서 이미지 삭제
            fileStoragePort.deleteProfileImage(user.getProfileImageUrl());

            // 4. User 엔티티 업데이트 (profileImageUrl = null)
            User updatedUser = user.toBuilder()
                    .profileImageUrl(null)
                    .build();
            userPersistencePort.save(updatedUser);

            log.info("프로필 이미지 삭제 완료 - userId: {}", userId);
            return ResponseEntity.ok(UserDto.DeleteProfileImageResponse.builder()
                    .success(true)
                    .message("프로필 이미지가 삭제되었습니다")
                    .build());

        } catch (Exception e) {
            log.error("프로필 이미지 삭제 실패 - userId: {}, error: {}", userId, e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(UserDto.DeleteProfileImageResponse.builder()
                            .success(false)
                            .message(e.getMessage())
                            .build());
        }
    }

    @Override
    public ResponseEntity<UserDto.UpdatePasswordResponse> updatePassword(Long userId, UserDto.UpdatePasswordRequest request) {
        log.info("비밀번호 변경 시작 - userId: {}", userId);

        // 1. 사용자 조회
        User user = userPersistencePort.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(UserDto.UpdatePasswordResponse.builder()
                            .success(false)
                            .message("사용자를 찾을 수 없습니다")
                            .build());
        }

        // 2. 현재 비밀번호 검증
        if (!bCryptPasswordEncoder.matches(request.getCurrentPassword().toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(UserDto.UpdatePasswordResponse.builder()
                            .success(false)
                            .message("현재 비밀번호가 일치하지 않습니다")
                            .build());
        }

        // 3. 새 비밀번호 유효성 검증
        String passwordValidationMessage = PasswordValidator.getValidationMessage(request.getNewPassword());
        if (passwordValidationMessage != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(UserDto.UpdatePasswordResponse.builder()
                            .success(false)
                            .message(passwordValidationMessage)
                            .build());
        }

        // 4. 기존 비밀번호와 일치하는지 확인
        if (bCryptPasswordEncoder.matches(request.getNewPassword().toLowerCase(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(UserDto.UpdatePasswordResponse.builder()
                            .success(false)
                            .message("새 비밀번호는 기존 비밀번호와 달라야 합니다")
                            .build());
        }

        // 5. 비밀번호 변경
        User updatedUser = user.toBuilder()
                .password(bCryptPasswordEncoder.encode(request.getNewPassword().toLowerCase()))
                .build();
        userPersistencePort.save(updatedUser);

        log.info("비밀번호 변경 완료 - userId: {}", userId);
        return ResponseEntity.ok(UserDto.UpdatePasswordResponse.builder()
                .success(true)
                .message("비밀번호가 변경되었습니다")
                .build());
    }

    /**
     * 파일 확장자 추출
     * @param filename 파일명
     * @return 소문자 확장자 (확장자 없으면 빈 문자열)
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf(".") + 1).toLowerCase();
    }
}
