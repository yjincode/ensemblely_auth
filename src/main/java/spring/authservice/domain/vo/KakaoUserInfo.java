package spring.authservice.domain.vo;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 카카오 사용자 정보 응답
 * API: https://kapi.kakao.com/v2/user/me
 */
@Getter
@NoArgsConstructor
public class KakaoUserInfo {

    @JsonProperty("id")
    private Long id;  // 카카오 고유 ID

    @JsonProperty("kakao_account")
    private KakaoAccount kakaoAccount;

    @Getter
    @NoArgsConstructor
    public static class KakaoAccount {

        @JsonProperty("profile")
        private Profile profile;

        @Getter
        @NoArgsConstructor
        public static class Profile {

            @JsonProperty("nickname")
            private String nickname;

            @JsonProperty("profile_image_url")
            private String profileImageUrl;
        }
    }

    /**
     * 사용자 정보 조회 성공 여부
     */
    public boolean isSuccess() {
        return id != null && kakaoAccount != null;
    }

    /**
     * 카카오 ID (문자열 변환)
     */
    public String getKakaoId() {
        return id != null ? String.valueOf(id) : null;
    }

    /**
     * 닉네임 추출
     */
    public String getNickname() {
        return kakaoAccount != null && kakaoAccount.getProfile() != null
                ? kakaoAccount.getProfile().getNickname()
                : null;
    }
}
