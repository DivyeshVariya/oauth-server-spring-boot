package io.itpl.oauthserver.controllers;

//import io.itpl.oauthserver.models.User;
//import io.itpl.oauthserver.services.UserDetailsServiceImpl;
import io.itpl.oauthserver.models.User;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping
//@Slf4j
public class AuthController {
  private final AuthenticationManager authenticationManager;

//  private final UserDetailsServiceImpl userDetailsService;

  @PostMapping("/register")
  public ResponseEntity<?> registerUser(@RequestBody User user) {
    try{
//    User user = userDetailsService.registerUser(userModel);
    System.out.println("USer "+user);
      UsernamePasswordAuthenticationToken authToken =
              new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(),
                      Collections.singleton(new SimpleGrantedAuthority("user")));

      Authentication authentication = authenticationManager.authenticate(authToken);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      // Return success response
      return ResponseEntity
              .ok().body(authentication.getName());
  } catch (AuthenticationException e) {
    // Handle authentication failure
    throw new RuntimeException("Invalid username or password");
  }
  }
  @GetMapping("/debug")
  public ResponseEntity<?> debug() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No authenticated user");
    }
    return ResponseEntity.ok(authentication.getName());
  }

}


