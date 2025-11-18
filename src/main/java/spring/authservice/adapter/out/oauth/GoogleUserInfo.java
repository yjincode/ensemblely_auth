package spring.authservice.adapter.out.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 구글 사용자 정보 응답 DTO
 * Google UserInfo API: https://www.googleapis.com/oauth2/v3/userinfo
 */
@Getter
@NoArgsConstructor
public class GoogleUserInfo {

    @JsonProperty("sub")
    private String sub;  // Google User ID

    @JsonProperty("email")
    private String email;

    @JsonProperty("email_verified")
    private Boolean emailVerified;

    @JsonProperty("name")
    private String name;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("family_name")
    private String familyName;

    @JsonProperty("picture")
    private String picture;

    /**
     * 구글 고유 ID 반환
     */
    public String getGoogleId() {
        return sub;
    }

    /**
     * 닉네임 반환 (name 우선, 없으면 givenName)
     */
    public String getNickname() {
        if (name != null && !name.isEmpty()) {
            return name;
        }
        if (givenName != null && !givenName.isEmpty()) {
            return givenName;
        }
        return null;
    }

    /**
     * 이메일 인증 여부 확인
     */
    public boolean isSuccess() {
        return email != null && !email.isEmpty();
    }
}
