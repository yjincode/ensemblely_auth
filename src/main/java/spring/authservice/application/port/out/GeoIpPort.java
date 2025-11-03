package spring.authservice.application.port.out;

/**
 * GeoIP 조회 Port (Outbound)
 * - MaxMind, IP2Location 등 다양한 구현체 가능
 */
public interface GeoIpPort {

    /**
     * IP 주소로 국가 코드 조회
     * @param ipAddress IP 주소
     * @return 국가 코드 (ISO 3166-1 alpha-2) 예: "KR", "US"
     */
    String getCountryCode(String ipAddress);
}
