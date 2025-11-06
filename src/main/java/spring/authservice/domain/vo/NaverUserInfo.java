package spring.authservice.domain.vo;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 네이버 사용자 정보 응답
 * API: https://openapi.naver.com/v1/nid/me
 */
@Getter
@NoArgsConstructor
public class NaverUserInfo {

    @JsonProperty("resultcode")
    private String resultCode;

    @JsonProperty("message")
    private String message;

    @JsonProperty("response")
    private Response response;

    @Getter
    @NoArgsConstructor
    public static class Response {

        @JsonProperty("id")
        private String id;  // 네이버 고유 ID

        @JsonProperty("email")
        private String email;

        @JsonProperty("name")
        private String name;

        @JsonProperty("nickname")
        private String nickname;

        @JsonProperty("profile_image")
        private String profileImage;
    }

    /**
     * 사용자 정보 조회 성공 여부
     */
    public boolean isSuccess() {
        return "00".equals(resultCode);
    }
}
