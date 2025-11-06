package spring.authservice.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final RedisTemplate<String, String> redisTemplate;
    private final TemplateEngine templateEngine;

    @Value("${server.port:9001}")
    private String serverPort;
    
    private static final String TOKEN_PREFIX = "token:";
    private static final String CODE_PREFIX = "code:";
    private static final String VERIFIED_PREFIX = "verified:";
    private static final String EMAIL_RATE_LIMIT_PREFIX = "email_rate_limit:";
    private static final String PASSWORD_RESET_CODE_PREFIX = "password_reset_code:";
    private static final String PASSWORD_RESET_VERIFIED_PREFIX = "password_reset_verified:";
    private static final int VERIFICATION_CODE_LENGTH = 6;
    private static final Duration VERIFICATION_CODE_TTL = Duration.ofMinutes(5);
    private static final Duration PASSWORD_RESET_VERIFIED_TTL = Duration.ofMinutes(10); // 비밀번호 재설정 인증 완료 유지 시간
    private static final Duration RATE_LIMIT_TTL = Duration.ofMinutes(1); // 1분간 제한
    private static final int MAX_EMAIL_PER_MINUTE = 1; // 1분에 1개 이메일만 허용
    private static final Duration DAILY_LIMIT_TTL = Duration.ofHours(24); // 24시간 제한
    private static final int MAX_EMAIL_PER_DAY = 10; // 하루에 10개 이메일만 허용
    
    /**
     * 6자리 숫자 인증코드 생성
     */
    public String generateVerificationCode() {
        SecureRandom random = new SecureRandom();
        StringBuilder code = new StringBuilder();
        
        for (int i = 0; i < VERIFICATION_CODE_LENGTH; i++) {
            code.append(random.nextInt(10));
        }
        
        return code.toString();
    }
    
    /**
     * 이메일 인증 발송 (코드 + 링크 둘 다 발송)
     * 양방향 참조 패턴: token:{token} ↔ code:{code}
     */
    public RateLimitResult sendVerificationEmail(String email) {
        // 1. Rate Limiting 체크
        RateLimitResult rateLimitResult = checkRateLimit(email);
        if (rateLimitResult != RateLimitResult.ALLOWED) {
            log.warn("이메일 발송 제한 초과: {} - {}", email, rateLimitResult);
            return rateLimitResult;
        }

        try {
            // 2. 인증코드 및 토큰 생성
            String verificationCode = generateVerificationCode();
            String verificationToken = UUID.randomUUID().toString().replace("-", "");

            // token:{token} → email:code
            String tokenKey = TOKEN_PREFIX + verificationToken;
            String tokenValue = email + ":" + verificationCode;
            redisTemplate.opsForValue().set(tokenKey, tokenValue, VERIFICATION_CODE_TTL);

            // code:{code} → email:token
            String codeKey = CODE_PREFIX + verificationCode;
            String codeValue = email + ":" + verificationToken;
            redisTemplate.opsForValue().set(codeKey, codeValue, VERIFICATION_CODE_TTL);

            log.info("양방향 참조 Redis 저장 완료 - email: {}, token: {}, code: {}", email, verificationToken, verificationCode);

            // 3. HTML 이메일 발송 (코드 + 링크)
            sendHtmlEmail(email, verificationCode, verificationToken);

            // 4. Rate Limit 카운터 증가
            incrementRateLimit(email);

            log.info("이메일 인증 발송 성공: {}", email);
            return RateLimitResult.ALLOWED;

        } catch (MailException | MessagingException e) {
            log.error("이메일 발송 실패: {}, 오류: {}", email, e.getMessage());
            return RateLimitResult.ALLOWED; // 실패해도 재시도 가능하도록
        } catch (Exception e) {
            log.error("인증 발송 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return RateLimitResult.ALLOWED; // 실패해도 재시도 가능하도록
        }
    }
    
    /**
     * HTML 이메일 발송 (코드 + 링크)
     */
    private void sendHtmlEmail(String email, String verificationCode, String verificationToken) throws MessagingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        // Thymeleaf 컨텍스트 설정
        Context context = new Context();
        context.setVariable("showCode", true);
        context.setVariable("showLink", true);
        context.setVariable("verificationCode", verificationCode);
        String verificationUrl = "http://localhost:" + serverPort + "/auths/verify-email?token=" + verificationToken;
        context.setVariable("verificationUrl", verificationUrl);

        // HTML 템플릿 렌더링
        String htmlContent = templateEngine.process("email-verification", context);

        // 이메일 설정
        helper.setTo(email);
        helper.setSubject("🎵 앙상블리 - 이메일 인증");
        helper.setText(htmlContent, true); // HTML 모드

        mailSender.send(mimeMessage);
    }
    
    /**
     * 이메일 인증코드 검증 (양방향 참조 패턴)
     */
    public boolean verifyEmailCode(String email, String inputCode) {
        try {
            // code:{code} → email:token
            String codeKey = CODE_PREFIX + inputCode;
            String codeValue = redisTemplate.opsForValue().get(codeKey);

            if (codeValue == null) {
                log.warn("인증코드가 만료되거나 존재하지 않음: {}", inputCode);
                return false;
            }

            String[] parts = codeValue.split(":");
            String storedEmail = parts[0];
            String token = parts[1];

            // 이메일 일치 확인
            if (!storedEmail.equals(email)) {
                log.warn("이메일 불일치 - 입력: {}, 저장: {}", email, storedEmail);
                return false;
            }

            // 인증 성공 - 양방향 키 모두 삭제
            String tokenKey = TOKEN_PREFIX + token;
            redisTemplate.delete(codeKey);
            redisTemplate.delete(tokenKey);

            log.info("이메일 인증 성공 (코드 방식): {}", email);
            return true;

        } catch (Exception e) {
            log.error("인증코드 검증 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return false;
        }
    }

    /**
     * 단순 토큰으로 이메일 인증 후 이메일 주소 반환 (양방향 참조 패턴)
     */
    public String verifyEmailByTokenAndGetEmail(String token) {
        try {
            // token:{token} → email:code
            String tokenKey = TOKEN_PREFIX + token;
            String tokenValue = redisTemplate.opsForValue().get(tokenKey);

            if (tokenValue == null) {
                log.warn("토큰이 만료되거나 존재하지 않음: {}", token);
                return null;
            }

            String[] parts = tokenValue.split(":");
            String email = parts[0];
            String code = parts[1];

            // 인증 성공 - 양방향 키 모두 삭제
            String codeKey = CODE_PREFIX + code;
            redisTemplate.delete(tokenKey);
            redisTemplate.delete(codeKey);

            log.info("토큰 기반 이메일 인증 성공: {} (token: {})", email, token);
            return email;

        } catch (Exception e) {
            log.error("토큰 인증 중 예외 발생: 오류: {}", e.getMessage());
            return null;
        }
    }
    
    
    /**
     * Rate Limiting 체크 결과
     */
    public enum RateLimitResult {
        ALLOWED,           // 허용
        MINUTE_LIMIT,      // 1분 제한 초과
        DAILY_LIMIT        // 일일 제한 초과
    }

    /**
     * Rate Limiting 체크 (1분에 1개, 하루에 10개 제한)
     */
    public RateLimitResult checkRateLimit(String email) {
        try {
            // 1분 제한 체크
            String minuteKey = EMAIL_RATE_LIMIT_PREFIX + "minute:" + email;
            String minuteCount = redisTemplate.opsForValue().get(minuteKey);

            if (minuteCount != null && Integer.parseInt(minuteCount) >= MAX_EMAIL_PER_MINUTE) {
                log.warn("1분 이메일 발송 제한 초과: {} (현재: {}개)", email, minuteCount);
                return RateLimitResult.MINUTE_LIMIT;
            }

            // 하루 제한 체크
            String dailyKey = EMAIL_RATE_LIMIT_PREFIX + "daily:" + email;
            String dailyCount = redisTemplate.opsForValue().get(dailyKey);

            if (dailyCount != null && Integer.parseInt(dailyCount) >= MAX_EMAIL_PER_DAY) {
                log.warn("일일 이메일 발송 제한 초과: {} (현재: {}개)", email, dailyCount);
                return RateLimitResult.DAILY_LIMIT;
            }

            return RateLimitResult.ALLOWED;

        } catch (Exception e) {
            log.error("Rate limiting 체크 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return RateLimitResult.ALLOWED; // 에러 시에는 허용
        }
    }
    
    /**
     * Rate Limiting 카운터 증가
     */
    private void incrementRateLimit(String email) {
        try {
            // 1분 카운터 증가
            String minuteKey = EMAIL_RATE_LIMIT_PREFIX + "minute:" + email;
            String currentMinuteCount = redisTemplate.opsForValue().get(minuteKey);
            
            if (currentMinuteCount == null) {
                redisTemplate.opsForValue().set(minuteKey, "1", RATE_LIMIT_TTL);
            } else {
                redisTemplate.opsForValue().increment(minuteKey);
            }
            
            // 하루 카운터 증가
            String dailyKey = EMAIL_RATE_LIMIT_PREFIX + "daily:" + email;
            String currentDailyCount = redisTemplate.opsForValue().get(dailyKey);
            
            if (currentDailyCount == null) {
                redisTemplate.opsForValue().set(dailyKey, "1", DAILY_LIMIT_TTL);
            } else {
                redisTemplate.opsForValue().increment(dailyKey);
            }
            
            log.debug("Rate limit 카운터 증가: {} (1분: {}, 하루: {})", email, 
                    redisTemplate.opsForValue().get(minuteKey), 
                    redisTemplate.opsForValue().get(dailyKey));
                    
        } catch (Exception e) {
            log.error("Rate limiting 카운터 증가 중 예외 발생: {}, 오류: {}", email, e.getMessage());
        }
    }

    // === 비밀번호 재설정 관련 ===

    /**
     * 비밀번호 재설정 인증코드 발송
     */
    public RateLimitResult sendPasswordResetCode(String email) {
        // 1. Rate Limiting 체크
        RateLimitResult rateLimitResult = checkRateLimit(email);
        if (rateLimitResult != RateLimitResult.ALLOWED) {
            log.warn("비밀번호 재설정 이메일 발송 제한 초과: {} - {}", email, rateLimitResult);
            return rateLimitResult;
        }

        try {
            // 2. 인증코드 생성 및 Redis 저장
            String verificationCode = generateVerificationCode();
            String redisKey = PASSWORD_RESET_CODE_PREFIX + email;
            redisTemplate.opsForValue().set(redisKey, verificationCode, VERIFICATION_CODE_TTL);
            log.info("비밀번호 재설정 인증코드 Redis 저장 완료: {}", email);

            // 3. 이메일 발송
            sendPasswordResetEmail(email, verificationCode);

            // 4. Rate Limit 카운터 증가
            incrementRateLimit(email);

            log.info("비밀번호 재설정 인증코드 발송 성공: {}", email);
            return RateLimitResult.ALLOWED;

        } catch (MailException | MessagingException e) {
            log.error("비밀번호 재설정 이메일 발송 실패: {}, 오류: {}", email, e.getMessage());
            return RateLimitResult.ALLOWED; // 실패해도 재시도 가능하도록
        } catch (Exception e) {
            log.error("비밀번호 재설정 코드 발송 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return RateLimitResult.ALLOWED; // 실패해도 재시도 가능하도록
        }
    }

    /**
     * 비밀번호 재설정 이메일 발송
     */
    private void sendPasswordResetEmail(String email, String verificationCode) throws MessagingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        // Thymeleaf 컨텍스트 설정
        Context context = new Context();
        context.setVariable("verificationCode", verificationCode);

        // HTML 템플릿 렌더링
        String htmlContent = templateEngine.process("password-reset-email", context);

        // 이메일 설정
        helper.setTo(email);
        helper.setSubject("🎵 앙상블리 - 비밀번호 재설정");
        helper.setText(htmlContent, true); // HTML 모드

        mailSender.send(mimeMessage);
    }

    /**
     * 비밀번호 재설정 인증코드 검증
     */
    public boolean verifyPasswordResetCode(String email, String inputCode) {
        try {
            String redisKey = PASSWORD_RESET_CODE_PREFIX + email;
            String storedCode = redisTemplate.opsForValue().get(redisKey);

            if (storedCode == null) {
                log.warn("비밀번호 재설정 인증코드가 만료되거나 존재하지 않음: {}", email);
                return false;
            }

            boolean isValid = storedCode.equals(inputCode);

            if (isValid) {
                // 인증 성공시 Redis에서 코드 삭제하고 인증 완료 저장
                redisTemplate.delete(redisKey);
                String verifiedKey = PASSWORD_RESET_VERIFIED_PREFIX + email;
                redisTemplate.opsForValue().set(verifiedKey, "verified", PASSWORD_RESET_VERIFIED_TTL);
                log.info("비밀번호 재설정 인증 성공: {}", email);
            } else {
                log.warn("잘못된 비밀번호 재설정 인증코드 입력: {}", email);
            }

            return isValid;

        } catch (Exception e) {
            log.error("비밀번호 재설정 인증코드 검증 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return false;
        }
    }

    /**
     * 비밀번호 재설정 인증 완료 여부 확인
     */
    public boolean isPasswordResetVerified(String email) {
        String verifiedKey = PASSWORD_RESET_VERIFIED_PREFIX + email;
        String value = redisTemplate.opsForValue().get(verifiedKey);
        return "verified".equals(value);
    }

    /**
     * 비밀번호 재설정 인증 정보 삭제 (비밀번호 변경 후)
     */
    public void deletePasswordResetVerification(String email) {
        try {
            // 코드와 인증 완료 정보 모두 삭제
            String codeKey = PASSWORD_RESET_CODE_PREFIX + email;
            String verifiedKey = PASSWORD_RESET_VERIFIED_PREFIX + email;
            redisTemplate.delete(codeKey);
            redisTemplate.delete(verifiedKey);
            log.info("비밀번호 재설정 인증 정보 삭제 완료: {}", email);
        } catch (Exception e) {
            log.error("비밀번호 재설정 인증 정보 삭제 중 예외 발생: {}, 오류: {}", email, e.getMessage());
        }
    }
}