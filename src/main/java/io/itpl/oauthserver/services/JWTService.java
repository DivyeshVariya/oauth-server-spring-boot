//package io.itpl.oauthserver.services;
//
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.jwt.JwtClaimsSet;
//import org.springframework.security.oauth2.jwt.JwtEncoder;
//import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
//import org.springframework.stereotype.Service;
//
//import java.time.Instant;
//
//@Service
//public class JWTService {
//
//  private final JwtEncoder jwtEncoder;
//
//  public JWTService(JwtEncoder jwtEncoder) {
//    this.jwtEncoder = jwtEncoder;
//  }
//
//  public String generateToken(Authentication authentication) {
//    Instant now = Instant.now();
//
//    String scope = authentication.getAuthorities().stream()
//                                 .map(auth -> auth.getAuthority())
//                                 .reduce((a, b) -> a + " " + b).orElse("");
//
//    JwtClaimsSet claims = JwtClaimsSet.builder()
//                                      .issuer("self")
//                                      .issuedAt(now)
//                                      .expiresAt(now.plusSeconds(3600)) // Token validity: 1 hour
//                                      .subject(authentication.getName())
//                                      .claim("scope", scope)
//                                      .build();
//
//    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
//  }
//}
//
