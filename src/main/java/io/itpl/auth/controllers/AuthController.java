//package io.itpl.auth.controllers;
//
//import io.itpl.auth.contants.AppConstants;
//import io.itpl.auth.dto.request.AuthRequest;
//import io.itpl.auth.dto.response.Response;
//import io.itpl.auth.services.AccountManagementService;
//import jakarta.validation.Valid;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.Map;
//
//@CrossOrigin("*")
//@RequestMapping("/api/v1/auth-service/auth")
//@RestController
//public class AuthController {
//
//  private final AccountManagementService accountManagementService;
//  @Autowired
//  public AuthController(AccountManagementService accountManagementService) {
//    this.accountManagementService = accountManagementService;
//  }
//
//  @PostMapping("/login-or-register")
//  public ResponseEntity<Response> loginOrRegister(@RequestBody @Valid AuthRequest authRequest) {
//    String accessToken = accountManagementService.loginOrRegister(authRequest);
//    return ResponseEntity
//            .status(HttpStatus.OK)
//            .body(
//                    Response
//                            .builder()
//                            .status(HttpStatus.OK)
//                            .statusCode(HttpStatus.OK.value())
//                            .data(Map.of(AppConstants.DATA, accessToken))
//                            .build());
//  }
//}
