package io.itpl.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OTPRequest {
  @NotBlank(message = "mcc is required")
  private String mcc;
  @NotBlank(message = "mobileNumber is required")
  private String mobileNumber;
  private String otp;
  private String transactionId;
}
