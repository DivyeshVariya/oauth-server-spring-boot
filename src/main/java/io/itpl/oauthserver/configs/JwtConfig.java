package io.itpl.oauthserver.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
//@Configuration
//public class JwtConfig {
//
//  private RSAPublicKey publicKey;
//  private RSAPrivateKey privateKey;
//
//  public JwtConfig() throws Exception {
//    // Generate RSA Key Pair
//    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
//    this.publicKey = (RSAPublicKey) keyPair.getPublic();
//    this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
//  }
//
//  @Bean
//  public JwtEncoder jwtEncoder() {
//    return new NimbusJwtEncoder((jwkSelector, jwsHeader) -> jwkSelector.select(new JwsAlgorithm(JwsAlgorithm.),
//            this.publicKey));
//  }
//
//  @Bean
//  public JwtDecoder jwtDecoder() {
//    return NimbusJwtDecoder.withPublicKey(this.publicKey).build();
//  }
//
//  public RSAPublicKey getPublicKey() {
//    return publicKey;
//  }
//
//  public RSAPrivateKey getPrivateKey() {
//    return privateKey;
//  }
//}
//
