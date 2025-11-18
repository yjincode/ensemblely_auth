package spring.authservice.application.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import spring.authservice.domain.vo.UserDto;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 소셜 계정 통합을 위한 임시 검증 토큰 관리 서비스
 * - Redis에 소셜 계정 정보 저장 (5분 TTL)
 * - 중복 OAuth 검증 방지
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SocialMergeTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String MERGE_TOKEN_PREFIX = "social:merge:";
    private static final long MERGE_TOKEN_TTL_MINUTES = 5;  // 5분

    /**
     * 소셜 계정 정보를 Redis에 저장하고 임시 토큰 반환
     *
     * @param tokenData 소셜 계정 정보
     * @return 임시 검증 토큰 (UUID)
     */
    public String createMergeToken(UserDto.SocialMergeTokenData tokenData) {
        try {
            // UUID 생성
            String token = UUID.randomUUID().toString();
            String key = MERGE_TOKEN_PREFIX + token;

            // JSON 직렬화
            String jsonData = objectMapper.writeValueAsString(tokenData);

            // Redis 저장 (5분 TTL)
            redisTemplate.opsForValue().set(key, jsonData, MERGE_TOKEN_TTL_MINUTES, TimeUnit.MINUTES);

            log.info("소셜 머지 토큰 생성: token={}, provider={}, email={}",
                    token, tokenData.getProvider(), tokenData.getEmail());

            return token;

        } catch (JsonProcessingException e) {
            log.error("소셜 머지 토큰 데이터 직렬화 실패", e);
            throw new RuntimeException("토큰 생성 실패", e);
        }
    }


    /**
     * 임시 토큰으로 소셜 계정 정보 조회 (삭제하지 않음)
     *
     * @param token 임시 검증 토큰
     * @return 소셜 계정 정보 (없으면 null)
     */
    public UserDto.SocialMergeTokenData getMergeTokenData(String token) {
        try {
            String key = MERGE_TOKEN_PREFIX + token;

            String jsonData = redisTemplate.opsForValue().get(key);

            if (jsonData == null) {
                log.warn("소셜 머지 토큰 없음 또는 만료: token={}", token);
                return null;
            }

            // JSON 역직렬화
            UserDto.SocialMergeTokenData tokenData = objectMapper.readValue(
                    jsonData, UserDto.SocialMergeTokenData.class);

            log.info("소셜 머지 토큰 조회 성공: token={}, provider={}, email={}",
                    token, tokenData.getProvider(), tokenData.getEmail());

            return tokenData;

        } catch (JsonProcessingException e) {
            log.error("소셜 머지 토큰 데이터 역직렬화 실패", e);
            return null;
        }
    }

    /**
     * 임시 토큰 삭제
     *
     * @param token 임시 검증 토큰
     */
    public void deleteMergeToken(String token) {
        String key = MERGE_TOKEN_PREFIX + token;
        redisTemplate.delete(key);
        log.info("소셜 머지 토큰 삭제: token={}", token);
    }

    /**
     * 임시 토큰 검증 (삭제하지 않음)
     *
     * @param token 임시 검증 토큰
     * @return 유효 여부
     */
    public boolean isValidToken(String token) {
        String key = MERGE_TOKEN_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}
