//package io.itpl.oauthserver.configs;
//
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//
//public class ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {
//
//  private final String username;
//  private final String password;
//
//  public ResourceOwnerPasswordAuthenticationToken(String username, String password) {
//    super(null);
//    this.username = username;
//    this.password = password;
//    setAuthenticated(false);
//  }
//
//  @Override
//  public Object getCredentials() {
//    return this.password;
//  }
//
//  @Override
//  public Object getPrincipal() {
//    return this.username;
//  }
//}
//
//
