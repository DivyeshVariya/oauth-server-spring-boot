package io.itpl.auth.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
@Document(collection = "otp")
@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OTP {
  @Id
  private String id;
  private String otpCode;
  private Date generatedOn;
  private Date expiredOn;
  private String mobileNumber;
  private String mcc;
  private String transactionId;
  private boolean used;
}
