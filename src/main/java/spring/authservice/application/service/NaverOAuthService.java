package spring.authservice.application.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import spring.authservice.config.OAuth2Properties;
import spring.authservice.domain.vo.NaverUserInfo;

/**
 * 네이버 OAuth 검증 서비스
 * - Authorization Code를 Access Token으로 교환
 * - 사용자 정보 조회
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NaverOAuthService {

    private final OAuth2Properties oAuth2Properties;
    private final RestTemplate restTemplate = new RestTemplate();

    private static final String NAVER_TOKEN_URL = "https://nid.naver.com/oauth2.0/token";
    private static final String NAVER_USER_INFO_URL = "https://openapi.naver.com/v1/nid/me";


    public NaverUserInfo exchangeCodeForUserInfo(String code, String state) {
        try {
            // 1. Authorization Code → Access Token 교환
            String accessToken = getAccessToken(code, state);
            if (accessToken == null) {
                log.warn("네이버 액세스 토큰 발급 실패");
                return null;
            }

            // 2. Access Token으로 사용자 정보 조회
            return getUserInfo(accessToken);

        } catch (Exception e) {
            log.error("네이버 OAuth 처리 중 예상치 못한 오류 발생", e);
            return null;
        }
    }

    /**
     * Authorization Code를 Access Token으로 교환
     */
    private String getAccessToken(String code, String state) {
        try {
            String url = String.format(
                    "%s?grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&state=%s",
                    NAVER_TOKEN_URL,
                    oAuth2Properties.getNaver().getClientId(),
                    oAuth2Properties.getNaver().getClientSecret(),
                    code,
                    state
            );

            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    JsonNode.class
            );

            JsonNode body = response.getBody();
            if (body != null && body.has("access_token")) {
                String accessToken = body.get("access_token").asText();
                log.info("네이버 액세스 토큰 발급 성공");
                return accessToken;
            }

            return null;

        } catch (HttpClientErrorException e) {
            log.warn("네이버 토큰 교환 오류: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("네이버 토큰 교환 중 예상치 못한 오류 발생", e);
            return null;
        }
    }

    /**
     * Access Token으로 사용자 정보 조회
     */
    private NaverUserInfo getUserInfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + accessToken);

            ResponseEntity<NaverUserInfo> response = restTemplate.exchange(
                    NAVER_USER_INFO_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    NaverUserInfo.class
            );

            NaverUserInfo userInfo = response.getBody();

            if (userInfo != null && userInfo.isSuccess()) {
                log.info("네이버 사용자 정보 조회 성공: email={}", userInfo.getResponse().getEmail());
                return userInfo;
            } else {
                log.warn("네이버 사용자 정보 조회 실패: resultCode={}",
                        userInfo != null ? userInfo.getResultCode() : "null");
                return null;
            }

        } catch (HttpClientErrorException e) {
            log.warn("네이버 사용자 정보 조회 오류: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("네이버 사용자 정보 조회 중 예상치 못한 오류 발생", e);
            return null;
        }
    }
}