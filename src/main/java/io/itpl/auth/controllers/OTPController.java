//package io.itpl.auth.controllers;
//
//import io.itpl.auth.contants.AppConstants;
//import io.itpl.auth.dto.request.OTPRequest;
//import io.itpl.auth.dto.response.OTPResponse;
//import io.itpl.auth.dto.response.Response;
//import io.itpl.auth.services.OTPService;
//import jakarta.validation.Valid;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.Map;
//
//@CrossOrigin("*")
//@RequestMapping("/api/v1/auth-service/otp")
//@RestController
//public class OTPController {
//
//  private final OTPService OTPService;
//
//  @Autowired
//  public OTPController(OTPService otpService) {OTPService = otpService;}
//
//  @PostMapping("/request-otp")
//  public ResponseEntity<Response> requestOTP(@RequestBody @Valid OTPRequest otpRequest) {
//
//    OTPService.canResendOTP(otpRequest);
//
//    OTPResponse response = OTPService.generateOTP(otpRequest);
//    return ResponseEntity
//            .status(HttpStatus.OK)
//            .body(
//                    Response
//                            .builder()
//                            .status(HttpStatus.OK)
//                            .statusCode(HttpStatus.OK.value())
//                            .data(Map.of(AppConstants.DATA, response))
//                            .build());
//  }
//}
