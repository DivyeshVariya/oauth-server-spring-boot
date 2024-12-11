package io.itpl.oauthserver.repo;

import io.itpl.oauthserver.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepo extends MongoRepository<User, String> {
  Optional<User> findByEmailId(String emailId);

}
