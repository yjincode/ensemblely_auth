package spring.authservice.application.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import spring.authservice.adapter.out.oauth.GoogleUserInfo;
import spring.authservice.config.OAuth2Properties;

/**
 * 구글 OAuth 검증 서비스
 * - Authorization Code를 Access Token으로 교환
 * - 사용자 정보 조회
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final OAuth2Properties oAuth2Properties;
    private final RestTemplate restTemplate = new RestTemplate();

    private static final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";

    /**
     * Authorization Code를 Access Token으로 교환 후 사용자 정보 조회
     *
     * @param code 프론트엔드에서 받은 Authorization Code
     * @param redirectUri 구글에 등록된 Redirect URI
     * @return 구글 사용자 정보 (검증 실패 시 null)
     */
    public GoogleUserInfo exchangeCodeForUserInfo(String code, String redirectUri) {
        try {
            // 1. Authorization Code → Access Token 교환
            String accessToken = getAccessToken(code, redirectUri);
            if (accessToken == null) {
                log.warn("구글 액세스 토큰 발급 실패");
                return null;
            }

            // 2. Access Token으로 사용자 정보 조회
            return getUserInfo(accessToken);

        } catch (Exception e) {
            log.error("구글 OAuth 처리 중 예상치 못한 오류 발생", e);
            return null;
        }
    }

    /**
     * Authorization Code를 Access Token으로 교환
     */
    private String getAccessToken(String code, String redirectUri) {
        try {
            String clientId = oAuth2Properties.getGoogle().getClientId();
            String clientSecret = oAuth2Properties.getGoogle().getClientSecret();

            log.info("구글 토큰 교환 시도: clientId={}, clientSecret={}, redirectUri={}, code={}",
                    clientId != null ? clientId.substring(0, Math.min(15, clientId.length())) + "..." : "null",
                    clientSecret != null ? "존재" : "null",
                    redirectUri,
                    code != null ? "존재" : "null");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("redirect_uri", redirectUri);
            params.add("code", code);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    GOOGLE_TOKEN_URL,
                    HttpMethod.POST,
                    request,
                    JsonNode.class
            );

            JsonNode body = response.getBody();
            if (body != null && body.has("access_token")) {
                String accessToken = body.get("access_token").asText();
                log.info("구글 액세스 토큰 발급 성공");
                return accessToken;
            }

            return null;

        } catch (HttpClientErrorException e) {
            log.warn("구글 토큰 교환 오류: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("구글 토큰 교환 중 예상치 못한 오류 발생", e);
            return null;
        }
    }

    /**
     * Access Token으로 사용자 정보 조회
     */
    private GoogleUserInfo getUserInfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + accessToken);

            ResponseEntity<GoogleUserInfo> response = restTemplate.exchange(
                    GOOGLE_USER_INFO_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    GoogleUserInfo.class
            );

            GoogleUserInfo userInfo = response.getBody();

            if (userInfo != null && userInfo.isSuccess()) {
                log.info("구글 사용자 정보 조회 성공: email={}", userInfo.getEmail());
                return userInfo;
            } else {
                log.warn("구글 사용자 정보 조회 실패: userInfo=null");
                return null;
            }

        } catch (HttpClientErrorException e) {
            log.warn("구글 사용자 정보 조회 오류: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("구글 사용자 정보 조회 중 예상치 못한 오류 발생", e);
            return null;
        }
    }
}
