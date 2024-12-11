package io.itpl.oauthserver.config.jwtAuth;

import io.itpl.oauthserver.config.RSAKeyRecord;
import io.itpl.oauthserver.dto.TokenType;
import io.itpl.oauthserver.models.AccessToken;
import io.itpl.oauthserver.repo.AccessTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Optional;


@RequiredArgsConstructor
@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {
  private final AccessTokenRepository accessTokenRepository;
  private final RSAKeyRecord rsaKeyRecord;
  private final JwtTokenUtils jwtTokenUtils;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    try {
      log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started ");

      log.info("[JwtAccessTokenFilter:doFilterInternal]Filtering the Http Request:{}", request.getRequestURI());

      final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

      JwtDecoder jwtDecoder = NimbusJwtDecoder
              .withPublicKey(rsaKeyRecord.rsaPublicKey())
              .build();

      if (!authHeader.startsWith(TokenType.Bearer.name())) {
        filterChain.doFilter(request, response);
        return;
      }

      final String token = authHeader.substring(7);
      final Jwt jwtToken = jwtDecoder.decode(token);
      if (jwtToken==null) {
        log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to null jwt token");
        throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "Invalid JWT token");
      }
      Optional<AccessToken> byAccessToken = accessTokenRepository.findByAccessToken(token);
      if (byAccessToken.isPresent() && byAccessToken
              .get()
              .isRevoked()) {
        log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to token already revoked");
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Token already revoked");
      }

      final String userName = jwtTokenUtils.getUserName(jwtToken);

      if (!userName.isEmpty() && SecurityContextHolder
              .getContext()
              .getAuthentication()==null) {

        UserDetails userDetails = jwtTokenUtils.userDetails(userName);
        if (jwtTokenUtils.isTokenValid(jwtToken, userDetails)) {
          SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

          UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                  userDetails,
                  null,
                  userDetails.getAuthorities()
          );
          createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
          securityContext.setAuthentication(createdToken);
          SecurityContextHolder.setContext(securityContext);
        }
      }
      log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");

      filterChain.doFilter(request, response);
    } catch (JwtValidationException jwtValidationException) {
      log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to :{}", jwtValidationException.getMessage());
      throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
    }
  }
}
