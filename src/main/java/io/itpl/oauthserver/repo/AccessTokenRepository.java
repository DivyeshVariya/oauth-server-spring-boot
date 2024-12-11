package io.itpl.oauthserver.repo;

import io.itpl.oauthserver.models.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {
  Optional<AccessToken> findByAccessToken(String accessToken);
}
