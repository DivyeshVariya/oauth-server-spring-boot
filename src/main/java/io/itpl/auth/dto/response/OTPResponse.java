package io.itpl.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OTPResponse {
  private String id;
  private String otpCode;
  private Date generatedOn;
  private Date expiredOn;
  private String mobileNumber;
  private String mcc;
  private String transactionId;
  private Boolean used;
}
