package com.dailycodebuffer.client.repository;

import com.dailycodebuffer.client.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface UserRepository extends MongoRepository<User, String> {
  User findByEmail(String email);
}
