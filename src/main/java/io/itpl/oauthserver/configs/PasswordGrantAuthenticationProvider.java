//package io.itpl.oauthserver.configs;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.stereotype.Component;
//
//@Component
//public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {
//
//  private final AuthenticationManager authenticationManager;
//
//  public PasswordGrantAuthenticationProvider(AuthenticationManager authenticationManager) {
//    this.authenticationManager = authenticationManager;
//  }
//
//  @Override
//  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//    ResourceOwnerPasswordAuthenticationToken token = (ResourceOwnerPasswordAuthenticationToken) authentication;
//
//    // Authenticate user credentials
//    Authentication userAuth = new UsernamePasswordAuthenticationToken(
//            token.getPrincipal(), token.getCredentials());
//    return authenticationManager.authenticate(userAuth);
//  }
//
//  @Override
//  public boolean supports(Class<?> authentication) {
//    return ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
//  }
//}
//
