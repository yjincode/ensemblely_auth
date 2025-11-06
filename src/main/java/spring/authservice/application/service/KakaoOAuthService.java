package spring.authservice.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import spring.authservice.config.OAuth2Properties;
import spring.authservice.domain.vo.KakaoUserInfo;

/**
 * 카카오 OAuth 검증 서비스
 * - 프론트엔드에서 받은 Access Token을 카카오 API로 검증
 * - 사용자 정보 조회
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KakaoOAuthService {

    private final OAuth2Properties oAuth2Properties;
    private final RestTemplate restTemplate = new RestTemplate();

    private static final String KAKAO_USER_INFO_URL = "https://kapi.kakao.com/v2/user/me";

    /**
     * 카카오 Access Token 검증 및 사용자 정보 조회
     *
     * @param accessToken 프론트엔드에서 받은 카카오 Access Token
     * @return 카카오 사용자 정보 (검증 실패 시 null)
     */
    public KakaoUserInfo verifyToken(String accessToken) {
        try {
            // 1. HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + accessToken);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // 2. 카카오 사용자 정보 API 호출
            ResponseEntity<KakaoUserInfo> response = restTemplate.exchange(
                    KAKAO_USER_INFO_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    KakaoUserInfo.class
            );

            KakaoUserInfo userInfo = response.getBody();

            // 3. 응답 검증
            if (userInfo != null && userInfo.isSuccess()) {
                log.info("카카오 토큰 검증 성공: email={}", userInfo.getEmail());
                return userInfo;
            } else {
                log.warn("카카오 토큰 검증 실패: id={}", userInfo != null ? userInfo.getId() : "null");
                return null;
            }

        } catch (HttpClientErrorException e) {
            log.warn("카카오 토큰 검증 오류: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("카카오 토큰 검증 중 예상치 못한 오류 발생", e);
            return null;
        }
    }
}
