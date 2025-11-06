package spring.authservice.adapter.out.storage;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import spring.authservice.application.port.out.FileStoragePort;
import spring.authservice.config.S3Properties;

import java.io.InputStream;
import java.util.UUID;

/**
 * AWS S3 스토리지 어댑터
 * - 프로필 이미지 업로드/삭제 기능 제공
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class S3StorageAdapter implements FileStoragePort {

    private final S3Client s3Client;
    private final S3Properties s3Properties;

    private static final String PROFILE_IMAGE_PREFIX = "profile-images/";

    @Override
    public String uploadProfileImage(Long userId, String fileName, String contentType, InputStream inputStream, long contentLength) {
        try {
            String key = generateProfileImageKey(userId, fileName);

            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(s3Properties.getBucketName())
                    .key(key)
                    .contentType(contentType)
                    .contentLength(contentLength)
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, contentLength));

            String imageUrl = String.format("https://%s.s3.%s.amazonaws.com/%s",
                    s3Properties.getBucketName(),
                    s3Properties.getRegion(),
                    key);

            log.info("프로필 이미지 업로드 성공 - userId: {}, key: {}", userId, key);
            return imageUrl;

        } catch (S3Exception e) {
            log.error("S3 업로드 실패 - userId: {}, error: {}", userId, e.awsErrorDetails().errorMessage());
            throw new RuntimeException("프로필 이미지 업로드 실패", e);
        }
    }

    @Override
    public void deleteProfileImage(String imageUrl) {
        try {
            String key = extractKeyFromUrl(imageUrl);

            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(s3Properties.getBucketName())
                    .key(key)
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
            log.info("프로필 이미지 삭제 성공 - key: {}", key);

        } catch (S3Exception e) {
            log.error("S3 삭제 실패 - imageUrl: {}, error: {}", imageUrl, e.awsErrorDetails().errorMessage());
            throw new RuntimeException("프로필 이미지 삭제 실패", e);
        }
    }

    @Override
    public String extractKeyFromUrl(String imageUrl) {
        try {
            // https://bucket.s3.region.amazonaws.com/key 형식에서 key 추출
            int keyStartIndex = imageUrl.lastIndexOf(".com/") + 5;
            return imageUrl.substring(keyStartIndex);

        } catch (Exception e) {
            log.error("URL에서 키 추출 실패 - imageUrl: {}", imageUrl, e);
            throw new RuntimeException("잘못된 이미지 URL", e);
        }
    }

    /**
     * 프로필 이미지 S3 키 생성
     * 형식: profile-images/{userId}/{UUID}.{ext}
     */
    private String generateProfileImageKey(Long userId, String fileName) {
        String extension = getFileExtension(fileName);
        String uniqueFileName = UUID.randomUUID() + "." + extension;
        return PROFILE_IMAGE_PREFIX + userId + "/" + uniqueFileName;
    }

    /**
     * 파일 확장자 추출
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "jpg"; // 기본값
        }
        return filename.substring(filename.lastIndexOf(".") + 1).toLowerCase();
    }
}
