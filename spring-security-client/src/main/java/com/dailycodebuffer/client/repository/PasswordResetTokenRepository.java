package com.dailycodebuffer.client.repository;

import com.dailycodebuffer.client.entity.PasswordResetToken;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface PasswordResetTokenRepository extends
        MongoRepository<PasswordResetToken, String> {
  PasswordResetToken findByToken(String token);
}
