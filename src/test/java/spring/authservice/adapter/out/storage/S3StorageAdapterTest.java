package spring.authservice.adapter.out.storage;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import spring.authservice.config.S3Properties;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * S3StorageAdapter 단위 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("S3StorageAdapter 단위 테스트")
class S3StorageAdapterTest {

    @Mock
    private S3Client s3Client;

    @Mock
    private S3Properties s3Properties;

    @InjectMocks
    private S3StorageAdapter s3StorageAdapter;

    @Test
    @DisplayName("프로필 이미지 업로드 성공")
    void uploadProfileImage_Success() {
        // Given
        Long userId = 1L;
        String fileName = "profile.jpg";
        String contentType = "image/jpeg";
        InputStream inputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
        long contentLength = 3L;

        String bucketName = "test-bucket";
        String region = "ap-northeast-2";

        when(s3Properties.getBucketName()).thenReturn(bucketName);
        when(s3Properties.getRegion()).thenReturn(region);
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());

        // When
        String imageUrl = s3StorageAdapter.uploadProfileImage(userId, fileName, contentType, inputStream, contentLength);

        // Then
        assertThat(imageUrl).contains(bucketName);
        assertThat(imageUrl).contains(region);
        assertThat(imageUrl).contains("profile-images/" + userId);
        verify(s3Client, times(1)).putObject(any(PutObjectRequest.class), any(RequestBody.class));
    }

    @Test
    @DisplayName("프로필 이미지 업로드 실패 - S3 오류")
    void uploadProfileImage_S3Exception() {
        // Given
        Long userId = 1L;
        String fileName = "profile.jpg";
        String contentType = "image/jpeg";
        InputStream inputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
        long contentLength = 3L;

        when(s3Properties.getBucketName()).thenReturn("test-bucket");
        when(s3Properties.getRegion()).thenReturn("ap-northeast-2");
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenThrow(S3Exception.builder().message("S3 upload failed").build());

        // When & Then
        assertThatThrownBy(() ->
                s3StorageAdapter.uploadProfileImage(userId, fileName, contentType, inputStream, contentLength))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("프로필 이미지 업로드 실패");

        verify(s3Client, times(1)).putObject(any(PutObjectRequest.class), any(RequestBody.class));
    }

    @Test
    @DisplayName("프로필 이미지 삭제 성공")
    void deleteProfileImage_Success() {
        // Given
        String imageUrl = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/profile-images/1/20250101/uuid_profile.jpg";

        when(s3Properties.getBucketName()).thenReturn("test-bucket");
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        // When
        s3StorageAdapter.deleteProfileImage(imageUrl);

        // Then
        verify(s3Client, times(1)).deleteObject(any(DeleteObjectRequest.class));
    }

    @Test
    @DisplayName("프로필 이미지 삭제 실패 - S3 오류")
    void deleteProfileImage_S3Exception() {
        // Given
        String imageUrl = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/profile-images/1/profile.jpg";

        when(s3Properties.getBucketName()).thenReturn("test-bucket");
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenThrow(S3Exception.builder().message("S3 delete failed").build());

        // When & Then
        assertThatThrownBy(() -> s3StorageAdapter.deleteProfileImage(imageUrl))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("프로필 이미지 삭제 실패");

        verify(s3Client, times(1)).deleteObject(any(DeleteObjectRequest.class));
    }

    @Test
    @DisplayName("URL에서 키 추출 성공")
    void extractKeyFromUrl_Success() {
        // Given
        String imageUrl = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/profile-images/1/20250101/uuid_profile.jpg";
        String expectedKey = "profile-images/1/20250101/uuid_profile.jpg";

        // When
        String key = s3StorageAdapter.extractKeyFromUrl(imageUrl);

        // Then
        assertThat(key).isEqualTo(expectedKey);
    }

    @Test
    @DisplayName("URL에서 키 추출 성공 - 한글 파일명")
    void extractKeyFromUrl_KoreanFileName() {
        // Given
        String imageUrl = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/profile-images/1/20250101/uuid_%ED%94%84%ED%95%84.jpg";
        String expectedKey = "profile-images/1/20250101/uuid_프필.jpg";

        // When
        String key = s3StorageAdapter.extractKeyFromUrl(imageUrl);

        // Then
        assertThat(key).isEqualTo(expectedKey);
    }

    @Test
    @DisplayName("URL에서 키 추출 실패 - 잘못된 URL")
    void extractKeyFromUrl_InvalidUrl() {
        // Given
        String invalidUrl = "invalid-url";

        // When & Then
        assertThatThrownBy(() -> s3StorageAdapter.extractKeyFromUrl(invalidUrl))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("잘못된 이미지 URL");
    }
}
