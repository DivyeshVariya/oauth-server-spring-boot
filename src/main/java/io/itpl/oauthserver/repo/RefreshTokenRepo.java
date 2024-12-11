package io.itpl.oauthserver.repo;

import io.itpl.oauthserver.models.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends MongoRepository<RefreshToken, String> {

  Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
