package spring.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * OAuth2 설정 Properties
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "oauth2")
public class OAuth2Properties {

    private NaverConfig naver = new NaverConfig();
    private KakaoConfig kakao = new KakaoConfig();
    private GoogleConfig google = new GoogleConfig();

    @Getter
    @Setter
    public static class NaverConfig {
        private String clientId;
        private String clientSecret;
    }

    @Getter
    @Setter
    public static class KakaoConfig {
        private String clientId;
        private String redirectUri;
    }

    @Getter
    @Setter
    public static class GoogleConfig {
        private String clientId;
        private String clientSecret;
        private String redirectUri;
    }
}
