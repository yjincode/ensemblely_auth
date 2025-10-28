package spring.authservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring.authservice.config.JwtProperties;
import spring.authservice.domain.User;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtProperties jwtProperties;
    private static final long ACCESS_TOKEN_VALIDITY = 30 * 60 * 1000L; // 30분
    private static final long REFRESH_TOKEN_VALIDITY = 14 * 24 * 60 * 60 * 1000L; // 14일

    /**
     * Access Token + Refresh Token 생성
     * @return [accessToken, refreshToken]
     */
    public String[] generateTokens(User user) {
        Date now = new Date();
        Date accessExpiration = new Date(now.getTime() + ACCESS_TOKEN_VALIDITY);
        Date refreshExpiration = new Date(now.getTime() + REFRESH_TOKEN_VALIDITY);

        String accessToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("nickname", user.getNickname())  // 프론트엔드에서 사용
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now)
                .setExpiration(accessExpiration)
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now)
                .setExpiration(refreshExpiration)
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();

        return new String[]{accessToken, refreshToken};
    }

    /**
     * Refresh Token에서 userId 추출
     * @param token Refresh Token
     * @return userId (Long)
     * @throws ExpiredJwtException 만료된 토큰
     * @throws MalformedJwtException 잘못된 형식의 토큰
     */
    public Long getUserIdFromRefreshToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    /**
     * Access Token에서 userId 추출
     * @param token Access Token
     * @return userId (Long)
     * @throws ExpiredJwtException 만료된 토큰
     * @throws MalformedJwtException 잘못된 형식의 토큰
     */
    public Long getUserIdFromAccessToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    /**
     * Access Token 유효성 검증
     * @param token Access Token
     * @return 유효하면 true, 아니면 false
     */
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey())
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            return false;
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Refresh Token 유효성 검증
     * @param token Refresh Token
     * @return 유효하면 true, 아니면 false
     */
    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey())
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            // 만료된 토큰
            return false;
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            // 잘못된 토큰
            return false;
        }
    }

    /**
     * Access Token 만료 시간 (초 단위)
     */
    public long getAccessTokenExpiresIn() {
        return ACCESS_TOKEN_VALIDITY / 1000; // 밀리초 → 초
    }
}