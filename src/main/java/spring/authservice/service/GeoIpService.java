package spring.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * GeoIP 서비스
 * - IP 주소로부터 국가 코드 추출
 * - 현재는 기본값 "KR" 반환 (추후 MaxMind GeoIP2 통합 가능)
 */
@Slf4j
@Service
public class GeoIpService {

    /**
     * IP 주소로부터 국가 코드 조회
     * @param ipAddress IP 주소
     * @return ISO 3166-1 alpha-2 국가 코드 (예: "KR", "US")
     */
    public String getCountryCode(String ipAddress) {
        // TODO: MaxMind GeoIP2 라이브러리 통합
        // 현재는 기본값으로 한국("KR") 반환

        if (ipAddress == null || ipAddress.isEmpty()) {
            return "KR";
        }

        // 로컬 IP 체크
        if (isLocalIp(ipAddress)) {
            return "KR";
        }

        // TODO: 실제 GeoIP 조회 로직
        // DatabaseReader reader = new DatabaseReader.Builder(database).build();
        // CityResponse response = reader.city(InetAddress.getByName(ipAddress));
        // return response.getCountry().getIsoCode();

        log.debug("GeoIP lookup for IP: {} (returning default: KR)", ipAddress);
        return "KR";
    }

    /**
     * 로컬 IP 여부 확인
     */
    private boolean isLocalIp(String ip) {
        return ip.equals("127.0.0.1")
            || ip.equals("0:0:0:0:0:0:0:1")
            || ip.equals("::1")
            || ip.startsWith("192.168.")
            || ip.startsWith("10.")
            || ip.startsWith("172.16.")
            || ip.startsWith("172.17.")
            || ip.startsWith("172.18.")
            || ip.startsWith("172.19.")
            || ip.startsWith("172.20.")
            || ip.startsWith("172.21.")
            || ip.startsWith("172.22.")
            || ip.startsWith("172.23.")
            || ip.startsWith("172.24.")
            || ip.startsWith("172.25.")
            || ip.startsWith("172.26.")
            || ip.startsWith("172.27.")
            || ip.startsWith("172.28.")
            || ip.startsWith("172.29.")
            || ip.startsWith("172.30.")
            || ip.startsWith("172.31.");
    }
}
