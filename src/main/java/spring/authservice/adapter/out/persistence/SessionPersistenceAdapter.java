package spring.authservice.adapter.out.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import spring.authservice.application.port.out.SessionPersistencePort;
import spring.authservice.domain.model.RefreshTokenSession;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * RefreshTokenSession 영속성 어댑터
 * - RefreshTokenSessionRepository를 통해 세션 엔티티를 관리
 */
@Component
@RequiredArgsConstructor
public class SessionPersistenceAdapter implements SessionPersistencePort {

    private final RefreshTokenSessionRepository refreshTokenSessionRepository;

    @Override
    public RefreshTokenSession save(RefreshTokenSession session) {
        return refreshTokenSessionRepository.save(session);
    }

    @Override
    public List<RefreshTokenSession> findByUserId(Long userId) {
        return refreshTokenSessionRepository.findByUserId(userId);
    }

    @Override
    public Optional<RefreshTokenSession> findByRefreshTokenHash(String refreshTokenHash) {
        return refreshTokenSessionRepository.findByRefreshTokenHash(refreshTokenHash);
    }

    @Override
    @Transactional
    public void deleteById(UUID sessionId) {
        refreshTokenSessionRepository.deleteById(sessionId);
    }

    @Override
    @Transactional
    public void deleteByUserId(Long userId) {
        refreshTokenSessionRepository.deleteByUserId(userId);
    }

    @Override
    @Transactional
    public void deleteByCreatedAtBefore(LocalDateTime expiryDate) {
        refreshTokenSessionRepository.deleteByCreatedAtBefore(expiryDate);
    }

    @Override
    @Transactional
    public void updateLastUsedAt(String tokenHash, LocalDateTime now) {
        refreshTokenSessionRepository.updateLastUsedAt(tokenHash, now);
    }
}
