package io.itpl.auth.repository;

import io.itpl.auth.models.Account;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface AccountRepository extends MongoRepository<Account,String> {
  Account findByMobileNumber(String mcc,String mobileNumber);
}
