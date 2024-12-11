//package io.itpl.auth.services.impl;
//
//import io.itpl.auth.dto.request.AuthRequest;
//import io.itpl.auth.mappers.AccountMapper;
//import io.itpl.auth.models.Account;
//import io.itpl.auth.repository.AccountRepository;
//import io.itpl.auth.services.AccountManagementService;
//import io.itpl.auth.utils.JwtUtils;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//@Slf4j
//@Service
//public class AccountManagementServiceImpl implements AccountManagementService {
//
//  private final AccountRepository accountRepository;
//  private final JwtUtils jwtUtils;
//  private final AccountMapper accountMapper;
//
//  @Autowired
//  public AccountManagementServiceImpl(AccountRepository accountRepository, JwtUtils jwtUtils,
//                                      AccountMapper accountMapper) {
//    this.accountRepository = accountRepository;
//    this.jwtUtils = jwtUtils;
//    this.accountMapper = accountMapper;
//  }
//
//  @Override
//  public String loginOrRegister(final AuthRequest authRequest) {
//    log.trace("Inside the loginOrRegister method");
//    Account account = accountRepository.findByMobileNumber(authRequest.getMcc(),authRequest.getMobileNumber());
//
//    if (account == null) {
//      // Create account if not found
//      account = accountMapper.toEntity(authRequest);
//      account = accountRepository.save(account);
//      log.trace("Account created successfully with [{}]",account);
//    } else {
//      // Check if device already registered
//      log.trace("Account already exits with mcc [{}] mobileNumber [{}] deviceId [{}]",account.getMcc(),account.getMobileNumber(),account.getDeviceId());
//    }
//    // Generate token
//    return jwtUtils.generateToken(authRequest.getMobileNumber(),authRequest.getDeviceId());
//  }
//}
