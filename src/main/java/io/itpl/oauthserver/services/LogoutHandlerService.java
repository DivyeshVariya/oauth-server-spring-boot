package io.itpl.oauthserver.services;

import io.itpl.oauthserver.dto.TokenType;
import io.itpl.oauthserver.models.AccessToken;
import io.itpl.oauthserver.models.RefreshToken;
import io.itpl.oauthserver.repo.AccessTokenRepository;
import io.itpl.oauthserver.repo.RefreshTokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class LogoutHandlerService implements LogoutHandler {

  private final RefreshTokenRepo refreshTokenRepo;
  private final AccessTokenRepository accessTokenRepository;

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IllegalStateException {

    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (!authHeader.startsWith(TokenType.Bearer.name())) {
      return;
    }
    final String accessToken = authHeader.substring(7);
    Optional<AccessToken> accessToken1 = accessTokenRepository
            .findByAccessToken(accessToken);
    if (accessToken1.isPresent() && !accessToken1
            .get()
            .isRevoked()) {
      accessToken1
              .get()
              .setRevoked(Boolean.TRUE);
      AccessToken accessToken2 = accessTokenRepository.save(accessToken1.get());
      log.info("after setting access token revoked ture : " + accessToken2);
      log.info("Access token expiration done");
      Optional<RefreshToken> refreshTokenRepoById = refreshTokenRepo
              .findById(accessToken1
                      .get()
                      .getRefreshTokenId())
              .filter(f -> !f.isRevoked());
      if (refreshTokenRepoById.isPresent()) {
        refreshTokenRepoById
                .get()
                .setRevoked(Boolean.TRUE);
        RefreshToken refreshToken1 = refreshTokenRepo.save(refreshTokenRepoById.get());
        log.info("after setting refresh token revoked ture : " + refreshToken1);
        log.info("Refresh token expiration done");
      } else {
        log.error("Refresh token not found or already expiration done");
        throw new IllegalStateException("Refresh token not found or already expiration done");
      }
    } else {
      log.error("Access token not found or already expiration done");
      throw new IllegalStateException("Access token not found or already expiration done");
    }
  }
}
