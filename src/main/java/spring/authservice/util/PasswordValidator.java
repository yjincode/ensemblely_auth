package spring.authservice.util;

/**
 * 비밀번호 유효성 검증 유틸
 * - 8자리 이상 20자 이하
 * - 영문 + 숫자 포함 (특수문자 허용)
 */
public class PasswordValidator {

    public static String getValidationMessage(String password) {
        if (password == null || password.isEmpty()) {
            return "비밀번호를 입력해주세요";
        }
        if (password.length() < 8) {
            return "비밀번호는 8자리 이상이어야 합니다";
        }
        if (password.length() > 20) {
            return "비밀번호는 20자 이하여야 합니다";
        }
        if (!password.matches(".*[A-Za-z].*")) {
            return "비밀번호에 영문을 포함해야 합니다";
        }
        if (!password.matches(".*\\d.*")) {
            return "비밀번호에 숫자를 포함해야 합니다";
        }
        return null;
    }
}
