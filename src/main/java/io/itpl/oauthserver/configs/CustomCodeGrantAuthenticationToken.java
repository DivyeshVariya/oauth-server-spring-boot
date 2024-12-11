//package io.itpl.oauthserver.configs;
//
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//
//import java.util.Collection;
//import java.util.Map;
//
//public class CustomCodeGrantAuthenticationToken extends AbstractAuthenticationToken {
//
//  private final String code;
//  private final Authentication clientPrincipal;
//  private final Map<String, Object> additionalParameters;
//
//  public CustomCodeGrantAuthenticationToken(
//          String code,
//          Authentication clientPrincipal,
//          Map<String, Object> additionalParameters) {
//    super(null);
//    this.code = code;
//    this.clientPrincipal = clientPrincipal;
//    this.additionalParameters = additionalParameters;
//    setAuthenticated(false); // Mark the token as not authenticated
//  }
//
//  public String getCode() {
//    return code;
//  }
//
//  public Authentication getClientPrincipal() {
//    return clientPrincipal;
//  }
//
//  public Map<String, Object> getAdditionalParameters() {
//    return additionalParameters;
//  }
//
//  @Override
//  public Object getPrincipal() {
//    return clientPrincipal != null ? clientPrincipal.getPrincipal() : null;
//  }
//
//  @Override
//  public Object getCredentials() {
//    return code; // The code acts as credentials here
//  }
//
//  @Override
//  public Collection<GrantedAuthority> getAuthorities() {
//    return clientPrincipal != null ? (Collection<GrantedAuthority>) clientPrincipal.getAuthorities() : null;
//  }
//}
//
