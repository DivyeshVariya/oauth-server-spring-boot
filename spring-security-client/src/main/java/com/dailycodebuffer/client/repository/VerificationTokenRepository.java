package com.dailycodebuffer.client.repository;

import com.dailycodebuffer.client.entity.VerificationToken;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface VerificationTokenRepository extends
        MongoRepository<VerificationToken,String> {
    VerificationToken findByToken(String token);
}
