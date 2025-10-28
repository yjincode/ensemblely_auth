package spring.authservice.domain;

/**
 * 보안 감사 이벤트 유형
 */
public enum AuditEventType {
    /**
     * 세션 생성 (로그인)
     */
    SESSION_CREATED,

    /**
     * 세션 무효화 (단일 로그아웃)
     */
    SESSION_REVOKED,

    /**
     * 모든 세션 무효화 (전체 로그아웃 또는 비밀번호 변경)
     */
    ALL_SESSIONS_REVOKED,

    /**
     * 토큰으로 세션 무효화
     */
    SESSION_REVOKED_BY_TOKEN,

    /**
     * 블랙리스트 토큰 사용 시도 (보안 위협)
     */
    BLACKLISTED_TOKEN_ATTEMPT,

    /**
     * 토큰 갱신 (Refresh Token으로 Access Token 발급)
     */
    TOKEN_REFRESHED,

    /**
     * 토큰 검증 실패
     */
    TOKEN_VALIDATION_FAILED
}
