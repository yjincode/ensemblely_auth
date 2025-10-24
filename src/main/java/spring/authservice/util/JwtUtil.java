package spring.authservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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
        String accessToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("nickname", user.getNickname())  // 프론트엔드에서 사용
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();

        return new String[]{accessToken, refreshToken};
    }
}