package spring.authservice.adapter.out.external;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring.authservice.application.service.GeoIpService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * GeoIpAdapter 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GeoIpAdapter 단위 테스트")
class GeoIpAdapterTest {

    @Mock
    private GeoIpService geoIpService;

    @InjectMocks
    private GeoIpAdapter geoIpAdapter;

    @Test
    @DisplayName("국가 코드 조회 성공 - 한국")
    void getCountryCode_Korea() {
        // Given
        String ipAddress = "123.456.789.0";
        when(geoIpService.getCountryCode(ipAddress)).thenReturn("KR");

        // When
        String countryCode = geoIpAdapter.getCountryCode(ipAddress);

        // Then
        assertThat(countryCode).isEqualTo("KR");
        verify(geoIpService, times(1)).getCountryCode(ipAddress);
    }

    @Test
    @DisplayName("국가 코드 조회 성공 - 미국")
    void getCountryCode_USA() {
        // Given
        String ipAddress = "8.8.8.8";
        when(geoIpService.getCountryCode(ipAddress)).thenReturn("US");

        // When
        String countryCode = geoIpAdapter.getCountryCode(ipAddress);

        // Then
        assertThat(countryCode).isEqualTo("US");
        verify(geoIpService, times(1)).getCountryCode(ipAddress);
    }

    @Test
    @DisplayName("국가 코드 조회 실패 - Unknown")
    void getCountryCode_Unknown() {
        // Given
        String ipAddress = "127.0.0.1";
        when(geoIpService.getCountryCode(ipAddress)).thenReturn("Unknown");

        // When
        String countryCode = geoIpAdapter.getCountryCode(ipAddress);

        // Then
        assertThat(countryCode).isEqualTo("Unknown");
        verify(geoIpService, times(1)).getCountryCode(ipAddress);
    }
}
