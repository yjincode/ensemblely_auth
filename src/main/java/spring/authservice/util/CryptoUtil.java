package spring.authservice.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 암호화 유틸리티
 * - IP 주소 AES-256-GCM 암호화/복호화
 * - Refresh Token HMAC-SHA256 해싱
 */
@Slf4j
@Component
public class CryptoUtil {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int GCM_IV_LENGTH = 12;  // 96 bits
    private static final int GCM_TAG_LENGTH = 128;  // 128 bits

    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;

    public CryptoUtil(
            @Value("${security.encryption.aes-key}") String aesKeyBase64,
            @Value("${security.encryption.hmac-key}") String hmacKeyBase64
    ) {
        this.aesKey = new SecretKeySpec(
                Base64.getDecoder().decode(aesKeyBase64),
                "AES"
        );
        this.hmacKey = new SecretKeySpec(
                Base64.getDecoder().decode(hmacKeyBase64),
                HMAC_ALGORITHM
        );
    }

    /**
     * IP 주소 암호화 (AES-256-GCM)
     * @param plainText 평문 IP (예: "192.168.0.1")
     * @return Base64 인코딩된 암호문 (IV + ciphertext)
     */
    public String encryptIpAddress(String plainText) {
        try {
            // 랜덤 IV 생성
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // 암호화
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // IV + cipherText 결합
            byte[] encrypted = new byte[GCM_IV_LENGTH + cipherText.length];
            System.arraycopy(iv, 0, encrypted, 0, GCM_IV_LENGTH);
            System.arraycopy(cipherText, 0, encrypted, GCM_IV_LENGTH, cipherText.length);

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            log.error("IP 암호화 실패: {}", e.getMessage());
            throw new RuntimeException("IP 암호화 실패", e);
        }
    }

    /**
     * IP 주소 복호화 (AES-256-GCM)
     * @param encryptedBase64 Base64 인코딩된 암호문
     * @return 평문 IP
     */
    public String decryptIpAddress(String encryptedBase64) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);

            // IV 추출
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encrypted, 0, iv, 0, GCM_IV_LENGTH);

            // cipherText 추출
            byte[] cipherText = new byte[encrypted.length - GCM_IV_LENGTH];
            System.arraycopy(encrypted, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

            // 복호화
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("IP 복호화 실패: {}", e.getMessage());
            throw new RuntimeException("IP 복호화 실패", e);
        }
    }

    /**
     * Refresh Token 암호화 (AES-256-GCM)
     * @param token 원본 Refresh Token
     * @return Base64 인코딩된 암호문
     */
    public String encryptToken(String token) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
            byte[] cipherText = cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));

            // IV + cipherText 결합
            byte[] encrypted = new byte[GCM_IV_LENGTH + cipherText.length];
            System.arraycopy(iv, 0, encrypted, 0, GCM_IV_LENGTH);
            System.arraycopy(cipherText, 0, encrypted, GCM_IV_LENGTH, cipherText.length);

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            log.error("Token 암호화 실패: {}", e.getMessage());
            throw new RuntimeException("Token 암호화 실패", e);
        }
    }

    /**
     * Refresh Token 복호화 (AES-256-GCM)
     * @param encryptedBase64 Base64 인코딩된 암호문
     * @return 원본 Refresh Token
     */
    public String decryptToken(String encryptedBase64) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);

            // IV 추출
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encrypted, 0, iv, 0, GCM_IV_LENGTH);

            // cipherText 추출
            byte[] cipherText = new byte[encrypted.length - GCM_IV_LENGTH];
            System.arraycopy(encrypted, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

            // 복호화
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Token 복호화 실패: {}", e.getMessage());
            throw new RuntimeException("Token 복호화 실패", e);
        }
    }

    /**
     * Refresh Token HMAC-SHA256 해싱
     * @param token Refresh Token
     * @return Hex 인코딩된 HMAC (64자)
     */
    public String hashRefreshToken(String token) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(hmacKey);
            byte[] hash = mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            log.error("HMAC 해싱 실패: {}", e.getMessage());
            throw new RuntimeException("HMAC 해싱 실패", e);
        }
    }

    /**
     * byte[] → Hex 변환
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
