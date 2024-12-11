package io.itpl.oauthserver.configs;

//import io.itpl.oauthserver.services.CustomAuthenticationProvider;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
//import org.springframework.security.oauth2.client.web.reactive.function.client
// .ServletOAuth2AuthorizedClientExchangeFilterFunction;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.web.reactive.function.client.WebClient;
//
//@Configuration
//@EnableWebSecurity
//public class DefaultSecurityConfig {
//
//    @Autowired
//    private CustomAuthenticationProvider customAuthenticationProvider;
//
//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests(authorizeRequests ->
//                        authorizeRequests
////                                .requestMatchers("/login")
////                                         .permitAll()
//                                         .anyRequest()
//                                         .authenticated()
//                );
////        http.formLogin(Customizer.withDefaults()); // Default login page
////        http.oauth2Login(oauth2 -> oauth2.loginPage("/login")); // Custom login page
//        return http.build();
//    }
//
//    @Autowired
//    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
//        authenticationManagerBuilder
//                .authenticationProvider(customAuthenticationProvider);
//    }
//
//    @Bean
//    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
//        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
//                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
//        return WebClient
//                .builder()
//                .apply(oauth2Client.oauth2Configuration())
//                .build();
//    }
//
//    @Bean
//    OAuth2AuthorizedClientManager authorizedClientManager(
//            RegisteredClientRepository clientRegistrationRepository,
//            OAuth2AuthorizedClientRepository authorizedClientRepository) {
//
//        OAuth2AuthorizedClientProvider authorizedClientProvider =
//                OAuth2AuthorizedClientProviderBuilder
//                        .builder()
//                        .authorizationCode()
//                        .refreshToken()
//                        .build();
//        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
//                (ClientRegistrationRepository) clientRegistrationRepository, authorizedClientRepository);
//        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
//
//        return authorizedClientManager;
//    }
//}


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

  private static KeyPair generateRSAKeys() {
    KeyPair keyPair;

    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception exception) {
      throw new RuntimeException("failed to create keypair!");
    }

    return keyPair;
  }

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityChain(HttpSecurity httpSecurity,
                                                              RegisteredClientRepository registeredClientRepository,
                                                              HttpSessionSecurityContextRepository httpSessionSecurityContextRepository,OAuth2AuthorizationService authorizationService)
          throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

    httpSecurity
            .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .clientAuthentication(authentication -> {
              authentication.authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter());
              authentication.authenticationProvider(new PublicClientRefreshProvider(registeredClientRepository));
            })
            .tokenGenerator(tokenGenerator())
            .oidc(Customizer.withDefaults()); // enable open id connect 1.0

        httpSecurity.exceptionHandling(exception -> {
            exception.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

//        httpSecurity.exceptionHandling(exception -> {
//            exception.authenticationEntryPoint((request, response, authException) -> {
//              if (SecurityContextHolder
//                      .getContext().getAuthentication() == null) {
//                System.out.println("inside exception.authenticationEntryPoint");
//                UserDetails userDetails = new User("username", "password", List.of(new SimpleGrantedAuthority("user")));
//                UsernamePasswordAuthenticationToken authentication =
//                        new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
//                SecurityContextHolder
//                        .getContext()
//                        .setAuthentication(authentication);
//                System.out.println("end of exception.authentication");
//                request.getSession().getId();
//                httpSessionSecurityContextRepository.saveContext(SecurityContextHolder.getContext(),request,response);
//
//
//                // Generate authorization code
//                OAuth2Authorization authorization = OAuth2Authorization
//                        .withRegisteredClient(registeredClientRepository.findByClientId("public-client"))
//                        .principalName(authentication.getName())
//                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                        .attributes(attrs -> attrs.put(OAuth2ParameterNames.STATE, UUID.randomUUID().toString()))
//                        .build();
//                authorizationService.save(authorization);
//
////                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
////                        UUID.randomUUID().toString(),
////                        Instant.now(),
////                        Instant.now().plus(5, ChronoUnit.MINUTES)
////                );
//                // Generate the token
//                String authorizationCode = String.valueOf(authorization.getToken(OAuth2UserCode.class).getToken());
//
//                response.sendRedirect(request.getParameter("redirect_uri")!= null ? request.getParameter(
//                        "redirect_uri")+ "?code=" + authorizationCode : "/default-redirect");
//                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"Please authenticate.\"}");
//              } else {
//                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//                response.getWriter().write("{\"error\": \"Forbidden\", \"message\": \"Access denied.\"}");
//              }
//            });
//        });


    httpSecurity.oauth2ResourceServer(server -> {
      server.jwt(Customizer.withDefaults());
    });

    return httpSecurity.build();
  }

  @Bean
  public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
                                                         RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
  }

  @Bean
  public HttpSessionSecurityContextRepository getSessionSecurityContextRepository()
  {
    return new HttpSessionSecurityContextRepository();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityChain(HttpSecurity httpSecurity,HttpSessionSecurityContextRepository httpSessionSecurityContextRepository) throws Exception {
    httpSecurity.securityContext(securityContext -> securityContext
                    .securityContextRepository(httpSessionSecurityContextRepository));
    httpSecurity.csrf(AbstractHttpConfigurer::disable);
//        httpSecurity.authorizeHttpRequests(auth->auth.requestMatchers("/oauth2/**").authenticated());
    httpSecurity.authorizeHttpRequests(
            authorize -> authorize
                    .requestMatchers("/register", "/debug")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
    );

    httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
    httpSecurity.formLogin(Customizer.withDefaults());
//    httpSecurity.addFilterBefore(new CustomAuthenticationFilter(),AnonymousAuthenticationFilter.class);
    httpSecurity.csrf(AbstractHttpConfigurer::disable);

    // Disable the default form login flow since we are moving to a REST-based API
//    httpSecurity.formLogin(AbstractHttpConfigurer::disable);

    return httpSecurity.build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails userDetails = User
            .withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("user", "admin")
            .build();

    return new InMemoryUserDetailsManager(userDetails);
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient
            .withId(UUID
                    .randomUUID()
                    .toString())
            .clientId("public-client")
            .clientSecret("secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:8081/login/oauth2/code/public-client")
            .redirectUri("http://127.0.0.1:8080")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .tokenSettings(TokenSettings
                    .builder()
                    .reuseRefreshTokens(true)
                    .accessTokenTimeToLive(Duration.ofDays(7))
                    .refreshTokenTimeToLive(Duration.ofDays(30))
                    .build())
            .clientSettings(ClientSettings
                    .builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build())
            .build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRSAKeys();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    RSAKey build = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID
                    .randomUUID()
                    .toString())
            .build();

    JWKSet jwkSet = new JWKSet(build);
    return new ImmutableJWKSet<>(jwkSet);
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings
            .builder()
            .build();
  }

  OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
    return context -> {
      if (context
              .getTokenType()
              .getValue()
              .equals(OidcParameterNames.ID_TOKEN)) {
        Authentication principle = context.getPrincipal();
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : principle.getAuthorities()) {
          authorities.add(authority.getAuthority());
        }

        context
                .getClaims()
                .claim("authorities", authorities);
      }
    };
  }

  @Bean
  OAuth2TokenGenerator<?> tokenGenerator() {
    System.out.println("Inside the tokenGenerator");
    JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
    jwtGenerator.setJwtCustomizer(customizer());
    OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenOAuth2TokenGenerator = new CustomOAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(
            jwtGenerator
            ,
            refreshTokenOAuth2TokenGenerator
    );
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
          throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  private static final class PublicClientRefreshTokenAuthentication extends OAuth2ClientAuthenticationToken {

    public PublicClientRefreshTokenAuthentication(String clientId) {
      super(clientId, ClientAuthenticationMethod.NONE, null, null);
    }

    public PublicClientRefreshTokenAuthentication(RegisteredClient registeredClient) {
      super(registeredClient, ClientAuthenticationMethod.NONE, null);
    }
  }

  private static final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
      String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
      if (!grantType.equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
        return null;
      }

      String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
      if (!StringUtils.hasText(clientId)) {
        return null;
      }

      return new PublicClientRefreshTokenAuthentication(clientId);
    }
  }

  private static final class PublicClientRefreshProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;

    private PublicClientRefreshProvider(RegisteredClientRepository registeredClientRepository) {
      this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
      PublicClientRefreshTokenAuthentication publicClientRefreshTokenAuthentication =
              (PublicClientRefreshTokenAuthentication) authentication;

      if (!ClientAuthenticationMethod.NONE.equals(
              publicClientRefreshTokenAuthentication.getClientAuthenticationMethod())) {
        return null;
      }

      String clientId = publicClientRefreshTokenAuthentication
              .getPrincipal()
              .toString();
      RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

      if (registeredClient==null) {
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "client is not valid",
                null
        ));
      }

      if (!registeredClient
              .getClientAuthenticationMethods()
              .contains(
                      publicClientRefreshTokenAuthentication.getClientAuthenticationMethod()
              )) {
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "authentication_method is not register with client",
                null
        ));
      }
      return new PublicClientRefreshTokenAuthentication(registeredClient);
    }

    @Override
    public boolean supports(Class<?> authentication) {
      return PublicClientRefreshTokenAuthentication.class.isAssignableFrom(authentication);
    }
  }

  public final class CustomOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
    private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64
            .getUrlEncoder()
            .withoutPadding(), 96);

    public CustomOAuth2RefreshTokenGenerator() {
    }

    @Nullable
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
      System.out.println("Inside the generate method");
      if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
        System.out.println("Invalid token type");
        return null;
      } else {
        System.out.println("Generating refresh token");
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context
                .getRegisteredClient()
                .getTokenSettings()
                .getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
      }
    }
  }
}