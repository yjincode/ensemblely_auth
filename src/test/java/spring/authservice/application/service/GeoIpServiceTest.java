package spring.authservice.application.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * GeoIpService 테스트
 */
@DisplayName("GeoIpService 단위 테스트")
class GeoIpServiceTest {

    private final GeoIpService geoIpService = new GeoIpService();

    @Test
    @DisplayName("국가 코드 조회 - null IP는 KR 반환")
    void getCountryCode_NullIp_ReturnsKR() {
        // When
        String result = geoIpService.getCountryCode(null);

        // Then
        assertThat(result).isEqualTo("KR");
    }

    @Test
    @DisplayName("국가 코드 조회 - 빈 IP는 KR 반환")
    void getCountryCode_EmptyIp_ReturnsKR() {
        // When
        String result = geoIpService.getCountryCode("");

        // Then
        assertThat(result).isEqualTo("KR");
    }

    @Test
    @DisplayName("국가 코드 조회 - 로컬 IP는 KR 반환")
    void getCountryCode_LocalIp_ReturnsKR() {
        // When & Then
        assertThat(geoIpService.getCountryCode("127.0.0.1")).isEqualTo("KR");
        assertThat(geoIpService.getCountryCode("::1")).isEqualTo("KR");
        assertThat(geoIpService.getCountryCode("192.168.1.1")).isEqualTo("KR");
        assertThat(geoIpService.getCountryCode("10.0.0.1")).isEqualTo("KR");
    }

    @Test
    @DisplayName("국가 코드 조회 - 외부 IP는 기본값 KR 반환 (TODO: GeoIP 통합)")
    void getCountryCode_PublicIp_ReturnsKR() {
        // When
        String result = geoIpService.getCountryCode("8.8.8.8");

        // Then
        assertThat(result).isEqualTo("KR");
    }
}
