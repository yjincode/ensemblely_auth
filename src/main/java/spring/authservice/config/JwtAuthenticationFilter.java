package spring.authservice.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.authservice.service.RefreshTokenBlacklistService;
import spring.authservice.service.SecurityAuditService;
import spring.authservice.util.JwtUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

/**
 * JWT 인증 필터
 * - Refresh Token을 검증하여 인증 처리
 * - 게이트웨이에서 토큰 파싱하지 않고 Auth 서비스가 직접 검증
 * - 블랙리스트 확인 (Redis AOF - 영속성 보장)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final RefreshTokenBlacklistService blacklistService;
    private final SecurityAuditService auditService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1. 쿠키에서 Refresh Token 추출
        String refreshToken = extractRefreshTokenFromCookie(request);

        if (refreshToken != null) {
            try {
                // 2. 블랙리스트 확인 (Redis AOF - 영속성 보장)
                if (blacklistService.isBlacklisted(refreshToken)) {
                    String clientIp = getClientIp(request);

                    // 감사 로그: 블랙리스트 토큰 시도 (비동기 DB 저장)
                    auditService.logBlacklistedTokenAttempt(clientIp, request.getRequestURI());

                    log.warn("Blacklisted token detected from IP: {}", clientIp);
                    filterChain.doFilter(request, response);
                    return;
                }

                // 3. 토큰 유효성 검증 (만료, 서명)
                if (jwtUtil.validateRefreshToken(refreshToken)) {
                    // 4. userId 추출
                    Long userId = jwtUtil.getUserIdFromRefreshToken(refreshToken);

                    // 5. SecurityContext에 인증 정보 저장
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userId,
                                    null,
                                    Collections.emptyList()
                            );
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    log.debug("Authenticated user: {}", userId);
                }
            } catch (ExpiredJwtException e) {
                log.warn("Expired JWT token");
            } catch (MalformedJwtException e) {
                log.warn("Malformed JWT token");
            } catch (Exception e) {
                log.error("JWT authentication error: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * 쿠키에서 Refresh Token 추출
     */
    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }

    /**
     * 클라이언트 IP 추출
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // X-Forwarded-For에 여러 IP가 있을 경우 첫 번째 IP 사용
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }
}
