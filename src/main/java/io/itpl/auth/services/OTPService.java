package io.itpl.auth.services;

import io.itpl.auth.dto.request.AuthRequest;
import io.itpl.auth.dto.request.OTPRequest;
import io.itpl.auth.dto.response.OTPResponse;
import jakarta.validation.Valid;

public interface OTPService {
  OTPResponse generateOTP(final OTPRequest otpRequest);

  Boolean validateOTP(final OTPRequest otpRequest);

  void canResendOTP(final OTPRequest otpRequest);
}
