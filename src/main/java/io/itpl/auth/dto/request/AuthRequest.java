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
public class AuthRequest {
  @NotBlank(message = "mcc is required")
  private String mcc;
  @NotBlank(message = "mcc is mobileNumber")
  private String mobileNumber;
  @NotBlank(message = "mcc is deviceId")
  private String deviceId;
}
