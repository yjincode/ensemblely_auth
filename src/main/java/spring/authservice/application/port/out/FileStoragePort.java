package spring.authservice.application.port.out;

import java.io.InputStream;

/**
 * 파일 스토리지 Port (Outbound)
 * - AWS S3, Azure Blob, GCS 등 다양한 구현체 가능
 */
public interface FileStoragePort {

    /**
     * 프로필 이미지 업로드
     * @param userId 사용자 ID
     * @param fileName 파일명
     * @param contentType 파일 타입 (image/jpeg, image/png 등)
     * @param inputStream 파일 데이터
     * @param contentLength 파일 크기
     * @return 업로드된 파일의 URL
     */
    String uploadProfileImage(Long userId, String fileName, String contentType, InputStream inputStream, long contentLength);

    /**
     * 프로필 이미지 삭제
     * @param imageUrl 삭제할 이미지 URL
     */
    void deleteProfileImage(String imageUrl);

    /**
     * URL에서 파일 키 추출
     * @param imageUrl S3 URL
     * @return S3 객체 키
     */
    String extractKeyFromUrl(String imageUrl);
}
