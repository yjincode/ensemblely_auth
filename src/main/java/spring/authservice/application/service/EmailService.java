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
    
    private static final String EMAIL_VERIFICATION_PREFIX = "email_verification:";
    private static final String TOKEN_VERIFICATION_PREFIX = "email_verification_token:";
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
     */
    public boolean sendVerificationEmail(String email) {
        // 1. Rate Limiting 체크
        if (!checkRateLimit(email)) {
            log.warn("이메일 발송 제한 초과: {}", email);
            return false;
        }

        try {
            // 1. 인증코드 생성 및 Redis 저장
            String verificationCode = generateVerificationCode();
            String redisKey = EMAIL_VERIFICATION_PREFIX + email;
            redisTemplate.opsForValue().set(redisKey, verificationCode, VERIFICATION_CODE_TTL);
            log.info("인증코드 Redis 저장 완료: {}", email);

            // 2. 인증토큰 생성 및 Redis 저장
            String verificationToken = UUID.randomUUID().toString().replace("-", "");
            String tokenRedisKey = TOKEN_VERIFICATION_PREFIX + verificationToken;
            redisTemplate.opsForValue().set(tokenRedisKey, email, VERIFICATION_CODE_TTL);
            log.info("인증토큰 Redis 저장 완료: {} -> {}", verificationToken, email);

            // 3. HTML 이메일 발송 (코드 + 링크)
            sendHtmlEmail(email, verificationCode, verificationToken);

            // 4. Rate Limit 카운터 증가
            incrementRateLimit(email);

            log.info("이메일 인증 발송 성공: {}", email);
            return true;

        } catch (MailException | MessagingException e) {
            log.error("이메일 발송 실패: {}, 오류: {}", email, e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("인증 발송 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return false;
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
     * 이메일 인증코드 검증
     */
    public boolean verifyEmailCode(String email, String inputCode) {
        try {
            String redisKey = EMAIL_VERIFICATION_PREFIX + email;
            String storedCode = redisTemplate.opsForValue().get(redisKey);
            
            if (storedCode == null) {
                log.warn("인증코드가 만료되거나 존재하지 않음: {}", email);
                return false;
            }
            
            boolean isValid = storedCode.equals(inputCode);
            
            if (isValid) {
                // 인증 성공시 Redis에서 코드 삭제
                redisTemplate.delete(redisKey);
                log.info("이메일 인증 성공: {}", email);
            } else {
                log.warn("잘못된 인증코드 입력: {}", email);
            }
            
            return isValid;
            
        } catch (Exception e) {
            log.error("인증코드 검증 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return false;
        }
    }

    /**
     * 단순 토큰으로 이메일 인증 후 이메일 주소 반환
     */
    public String verifyEmailByTokenAndGetEmail(String token) {
        try {
            // 1. Redis에서 토큰으로 이메일 찾기
            String tokenRedisKey = TOKEN_VERIFICATION_PREFIX + token;
            String email = redisTemplate.opsForValue().get(tokenRedisKey);
            
            if (email == null) {
                log.warn("토큰이 만료되거나 존재하지 않음: {}", token);
                return null;
            }
            
            // 2. 인증 성공시 Redis에서 토큰과 코드 모두 삭제
            redisTemplate.delete(tokenRedisKey);
            String codeRedisKey = EMAIL_VERIFICATION_PREFIX + email;
            redisTemplate.delete(codeRedisKey);
            
            log.info("토큰 기반 이메일 인증 성공: {} (token: {})", email, token);
            return email;
            
        } catch (Exception e) {
            log.error("토큰 인증 중 예외 발생: 오류: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 특정 이메일의 인증코드와 토큰 삭제 (재발송 시 기존 데이터 제거용)
     */
    public void deleteVerificationCode(String email) {
        try {
            // 1. 코드 삭제
            String codeRedisKey = EMAIL_VERIFICATION_PREFIX + email;
            redisTemplate.delete(codeRedisKey);
            
            // 2. 해당 이메일의 기존 토큰들 찾아서 삭제
            Set<String> tokenKeys = redisTemplate.keys(TOKEN_VERIFICATION_PREFIX + "*");
            if (tokenKeys != null) {
                for (String tokenKey : tokenKeys) {
                    String storedEmail = redisTemplate.opsForValue().get(tokenKey);
                    if (email.equals(storedEmail)) {
                        redisTemplate.delete(tokenKey);
                    }
                }
            }
            
            log.info("기존 인증 데이터 삭제 완료: {}", email);
        } catch (Exception e) {
            log.error("인증 데이터 삭제 중 예외 발생: {}, 오류: {}", email, e.getMessage());
        }
    }
    
    /**
     * Rate Limiting 체크 (1분에 1개, 하루에 10개 제한)
     */
    private boolean checkRateLimit(String email) {
        try {
            // 1분 제한 체크
            String minuteKey = EMAIL_RATE_LIMIT_PREFIX + "minute:" + email;
            String minuteCount = redisTemplate.opsForValue().get(minuteKey);
            
            if (minuteCount != null && Integer.parseInt(minuteCount) >= MAX_EMAIL_PER_MINUTE) {
                log.warn("1분 이메일 발송 제한 초과: {} (현재: {}개)", email, minuteCount);
                return false;
            }
            
            // 하루 제한 체크
            String dailyKey = EMAIL_RATE_LIMIT_PREFIX + "daily:" + email;
            String dailyCount = redisTemplate.opsForValue().get(dailyKey);
            
            if (dailyCount != null && Integer.parseInt(dailyCount) >= MAX_EMAIL_PER_DAY) {
                log.warn("일일 이메일 발송 제한 초과: {} (현재: {}개)", email, dailyCount);
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            log.error("Rate limiting 체크 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return true; // 에러 시에는 허용
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
    public boolean sendPasswordResetCode(String email) {
        // 1. Rate Limiting 체크
        if (!checkRateLimit(email)) {
            log.warn("비밀번호 재설정 이메일 발송 제한 초과: {}", email);
            return false;
        }

        try {
            // 1. 인증코드 생성 및 Redis 저장
            String verificationCode = generateVerificationCode();
            String redisKey = PASSWORD_RESET_CODE_PREFIX + email;
            redisTemplate.opsForValue().set(redisKey, verificationCode, VERIFICATION_CODE_TTL);
            log.info("비밀번호 재설정 인증코드 Redis 저장 완료: {}", email);

            // 2. 이메일 발송
            sendPasswordResetEmail(email, verificationCode);

            // 3. Rate Limit 카운터 증가
            incrementRateLimit(email);

            log.info("비밀번호 재설정 인증코드 발송 성공: {}", email);
            return true;

        } catch (MailException | MessagingException e) {
            log.error("비밀번호 재설정 이메일 발송 실패: {}, 오류: {}", email, e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("비밀번호 재설정 코드 발송 중 예외 발생: {}, 오류: {}", email, e.getMessage());
            return false;
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