package spring.authservice.adapter.out.notification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.application.service.EmailService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * EmailAdapter 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailAdapter 단위 테스트")
class EmailAdapterTest {

    @Mock
    private EmailService emailService;

    @InjectMocks
    private EmailAdapter emailAdapter;

    @Test
    @DisplayName("이메일 인증 코드 발송")
    void sendVerificationEmail_Success() {
        // Given
        String email = "test@example.com";
        when(emailService.sendVerificationEmail(email)).thenReturn(true);

        // When
        boolean result = emailAdapter.sendVerificationEmail(email);

        // Then
        assertThat(result).isTrue();
        verify(emailService, times(1)).sendVerificationEmail(email);
    }

    @Test
    @DisplayName("이메일 인증 코드 검증")
    void verifyEmailCode_Success() {
        // Given
        String email = "test@example.com";
        String code = "123456";
        when(emailService.verifyEmailCode(email, code)).thenReturn(true);

        // When
        boolean result = emailAdapter.verifyEmailCode(email, code);

        // Then
        assertThat(result).isTrue();
        verify(emailService, times(1)).verifyEmailCode(email, code);
    }

    @Test
    @DisplayName("비밀번호 재설정 코드 발송")
    void sendPasswordResetCode_Success() {
        // Given
        String email = "test@example.com";
        when(emailService.sendPasswordResetCode(email)).thenReturn(true);

        // When
        boolean result = emailAdapter.sendPasswordResetCode(email);

        // Then
        assertThat(result).isTrue();
        verify(emailService, times(1)).sendPasswordResetCode(email);
    }

    @Test
    @DisplayName("비밀번호 재설정 코드 검증")
    void verifyPasswordResetCode_Success() {
        // Given
        String email = "test@example.com";
        String code = "123456";
        when(emailService.verifyPasswordResetCode(email, code)).thenReturn(true);

        // When
        boolean result = emailAdapter.verifyPasswordResetCode(email, code);

        // Then
        assertThat(result).isTrue();
        verify(emailService, times(1)).verifyPasswordResetCode(email, code);
    }
}
