package spring.authservice.application.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EmailService 테스트
 * - 복잡한 의존성(JavaMailSender, RedisTemplate 등)이 있어
 *   핵심 유틸리티 메서드만 단위 테스트
 * - 실제 이메일 발송은 통합 테스트에서 검증
 */
@DisplayName("EmailService 단위 테스트")
class EmailServiceTest {

    private final EmailService emailService = new EmailService(null, null, null);

    @Test
    @DisplayName("인증 코드 생성 - 6자리 숫자")
    void generateVerificationCode_Success() {
        // When
        String code = emailService.generateVerificationCode();

        // Then
        assertThat(code).hasSize(6);
        assertThat(code).matches("\\d{6}");
    }

    @Test
    @DisplayName("인증 코드 생성 - 매번 다른 코드 생성")
    void generateVerificationCode_UniqueValues() {
        // When
        String code1 = emailService.generateVerificationCode();
        String code2 = emailService.generateVerificationCode();

        // Then
        // 통계적으로 거의 항상 다를 것 (1/1,000,000 확률로 같을 수 있음)
        assertThat(code1).isNotEqualTo(code2);
    }
}
