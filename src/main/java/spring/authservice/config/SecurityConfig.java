package spring.authservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security 설정
 * - Auth 서비스는 자체적으로 Refresh Token 검증
 * - 공개 API: 회원가입, 로그인, 이메일 인증, 비밀번호 재설정
 * - 인증 필요 API: 토큰 재발급, 로그아웃
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 공개 API (인증 불필요)
                        .requestMatchers(
                                "/auths/register",                    // 회원가입
                                "/auths/check-userid",                // 아이디 중복 체크
                                "/auths/login",                       // 로그인
                                "/auths/email/send-verification",     // 이메일 인증 발송
                                "/auths/email/verify-code",           // 이메일 인증 코드 검증
                                "/auths/verify-email",                // 이메일 토큰 인증
                                "/auths/password/reset/send",         // 비밀번호 재설정 발송
                                "/auths/password/reset/verify",       // 비밀번호 재설정 검증
                                "/auths/password/reset/change"        // 비밀번호 변경
                        ).permitAll()
                        // 인증 필요 API
                        .requestMatchers(
                                "/auths/refresh",                     // 토큰 재발급
                                "/auths/logout",                      // 로그아웃
                                "/me/sessions",                       // 세션 목록 조회
                                "/me/sessions/**"                     // 세션 삭제
                        ).authenticated()
                        // 그 외 모든 요청 허용 (개발 편의)
                        .anyRequest().permitAll()
                )
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                // JWT 인증 필터 추가
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}