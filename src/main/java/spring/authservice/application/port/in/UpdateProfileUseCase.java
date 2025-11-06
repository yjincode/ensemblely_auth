package spring.authservice.application.port.in;

import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;
import spring.authservice.domain.vo.UserDto;

public interface UpdateProfileUseCase {

    ResponseEntity<UserDto.UploadProfileImageResponse> uploadProfileImage(Long userId, MultipartFile file);

    ResponseEntity<UserDto.DeleteProfileImageResponse> deleteProfileImage(Long userId);

    ResponseEntity<UserDto.UpdatePasswordResponse> updatePassword(Long userId, UserDto.UpdatePasswordRequest request);

}
