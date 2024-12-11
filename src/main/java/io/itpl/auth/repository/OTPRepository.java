package io.itpl.auth.repository;

import io.itpl.auth.models.OTP;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface OTPRepository extends MongoRepository<OTP,String> {
  OTP findByTransactionId(String transactionId);

  OTP findByMccAndMobileNumber(@NotBlank(message = "mcc is required") String mcc, @NotBlank(message = "mcc is mobileNumber") String mobileNumber);
}
