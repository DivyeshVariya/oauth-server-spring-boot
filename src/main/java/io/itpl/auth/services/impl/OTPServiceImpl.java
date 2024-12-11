package io.itpl.auth.services.impl;

import io.itpl.auth.dto.request.AuthRequest;
import io.itpl.auth.dto.request.OTPRequest;
import io.itpl.auth.dto.response.OTPResponse;
import io.itpl.auth.mappers.OTPMapper;
import io.itpl.auth.models.OTP;
import io.itpl.auth.repository.OTPRepository;
import io.itpl.auth.services.OTPService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Random;
import java.util.UUID;

@Slf4j
@Service
public class OTPServiceImpl implements OTPService {

  private static final long OTP_EXPIRATION_TIME = 60000; // 1 minute
  private final OTPMapper otpMapper;
  private final OTPRepository OTPRepository;

  @Autowired
  public OTPServiceImpl(OTPMapper otpMapper, io.itpl.auth.repository.OTPRepository otpRepository) {
    this.otpMapper = otpMapper;
    OTPRepository = otpRepository;}

  @Override
  public OTPResponse generateOTP(final OTPRequest otpRequest) {
    log.trace("Inside generateOTP method");
    Random rand = new Random();
    String otpCode = String.format("%06d", rand.nextInt(999999));
    log.trace("Generated OTP : [{}] for mobile: [{}]", otpCode, otpRequest.getMobileNumber());
    OTP newOTP =
    OTP.builder().otpCode(otpCode).generatedOn(new Date()).expiredOn(new Date(OTP_EXPIRATION_TIME)).mcc(otpRequest.getMcc()).mobileNumber(otpRequest.getMobileNumber()).transactionId(
            UUID.randomUUID().toString()).build();
    newOTP=OTPRepository.save(newOTP);
    log.trace("OTP generated with [{}]",newOTP);
    return otpMapper.toResponse(newOTP);
  }

  @Override
  public Boolean validateOTP(final OTPRequest otpRequest) {
    log.trace("Inside validateOTP method");
    OTP otpDetails = OTPRepository.findByTransactionId(otpRequest.getTransactionId());
    if (otpDetails == null)
    {
      log.error("Invalid Transaction Id");
      throw new RuntimeException("Invalid Transaction Id");
    }
    if(!otpRequest.getMcc().equals(otpDetails.getMcc()) || !otpRequest.getMobileNumber().equals(otpDetails.getMobileNumber()))
    {
      log.error("Invalid Mobile Number or MCC");
      throw new RuntimeException("Invalid Mobile Number or MCC");
    }
    if (otpDetails.getExpiredOn().equals(new Date())) {
      if(otpDetails.getOtpCode().equals(otpRequest.getOtp()))
      {
        if(otpDetails.isUsed())
        {
          log.error("OTP CODE already used");
          throw new RuntimeException("OTP CODE already used");
        }
        else{
          otpDetails.setUsed(Boolean.TRUE);
          log.trace("OTP CODE set to used [true]");
          return true;
      }
      }
      else{
        log.error("Invalid OTP CODE");
        throw new RuntimeException("Invalid OTP CODE");
      }
    }
    else{
      log.error("OTP expired");
      throw new RuntimeException("OTP expired");
    }
  }
  @Override
  public void canResendOTP(final OTPRequest otpRequest) {
    log.trace("Inside canResendOTP method");
    // Fetch OTP details from the repository
    OTP otpDetails = OTPRepository.findByMccAndMobileNumber(otpRequest.getMcc(), otpRequest.getMobileNumber());
    if (otpDetails != null) {
    // Check if the current time is less than 1 minute after the last OTP's expiredOn
    Date currentTime = new Date();
    long timeDifference = currentTime.getTime() - otpDetails.getGeneratedOn().getTime();
    if (timeDifference < 60 * 1000) {
      // 1 minute in milliseconds
      log.error("OTP was sent less than a minute ago. Please wait before requesting again.");
      throw new IllegalStateException("OTP was sent less than a minute ago. Please wait before requesting again.");
    }
    else
    {
      log.trace("Resend OTP request granted because OTP sent ago [{}]...",timeDifference);
    }
    }
  }
}
