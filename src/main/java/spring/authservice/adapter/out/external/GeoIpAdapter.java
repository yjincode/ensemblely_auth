package spring.authservice.adapter.out.external;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring.authservice.application.port.out.GeoIpPort;
import spring.authservice.application.service.GeoIpService;

/**
 * GeoIP 조회 어댑터
 * - GeoIpService를 통해 IP 주소로부터 국가 코드 조회
 */
@Component
@RequiredArgsConstructor
public class GeoIpAdapter implements GeoIpPort {

    private final GeoIpService geoIpService;

    @Override
    public String getCountryCode(String ipAddress) {
        return geoIpService.getCountryCode(ipAddress);
    }
}
