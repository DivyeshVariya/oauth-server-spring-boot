package io.itpl.oauthserver.services;

import io.itpl.oauthserver.config.jwtAuth.JwtTokenGenerator;
import io.itpl.oauthserver.dto.AuthResponseDto;
import io.itpl.oauthserver.dto.TokenType;
import io.itpl.oauthserver.dto.UserRegistrationDto;
import io.itpl.oauthserver.mapper.UserMapper;
import io.itpl.oauthserver.models.AccessToken;
import io.itpl.oauthserver.models.RefreshToken;
import io.itpl.oauthserver.models.User;
import io.itpl.oauthserver.repo.AccessTokenRepository;
import io.itpl.oauthserver.repo.RefreshTokenRepo;
import io.itpl.oauthserver.repo.UserRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
  private final UserRepo userInfoRepo;
  private final JwtTokenGenerator jwtTokenGenerator;
  private final RefreshTokenRepo refreshTokenRepo;
  private final UserMapper userInfoMapper;
  private final AccessTokenRepository accessTokenRepository;

  private static Authentication createAuthenticationObject(User userInfoEntity) {
    // Extract user details from UserDetailsEntity
    String username = userInfoEntity.getEmailId();
    String password = userInfoEntity.getPassword();
    String roles = userInfoEntity.getRoles();

    // Extract authorities from roles (comma-separated)
    String[] roleArray = roles.split(",");
    GrantedAuthority[] authorities = Arrays
            .stream(roleArray)
            .map(role -> (GrantedAuthority) role::trim)
            .toArray(GrantedAuthority[]::new);

    return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
  }

  public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
    try {
      var userInfoEntity = userInfoRepo
              .findByEmailId(authentication.getName())
              .orElseThrow(() -> {
                log.error("[AuthService:userSignInAuth] User :{} not found", authentication.getName());
                return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
              });


      String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
      String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
      //Let's save the refreshToken as well
      RefreshToken refreshTokenEntity =
              saveUserRefreshToken(userInfoEntity, refreshToken, JwtTokenGenerator.REFRESH_TOKEN_EXPIRY);
      //Let's save the accessToken as well
      saveUserAccessToken(userInfoEntity, accessToken, JwtTokenGenerator.ACCESS_TOKEN_EXPIRY,
              refreshTokenEntity.getId());
      //Creating the cookie
      creatRefreshTokenCookie(response, refreshToken);
      log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",
              userInfoEntity.getUserName());
      return AuthResponseDto
              .builder()
              .refreshToken(refreshToken)
              .accessToken(accessToken)
              .accessTokenExpiry(JwtTokenGenerator.ACCESS_TOKEN_EXPIRY)
              .userName(userInfoEntity.getUserName())
              .tokenType(TokenType.Bearer)
              .build();


    } catch (Exception e) {
      log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :" + e.getMessage());
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
    }
  }

  private RefreshToken saveUserRefreshToken(User userInfoEntity, String refreshToken, int expiry) {
    var refreshTokenEntity = RefreshToken
            .builder()
            .user(userInfoEntity)
            .refreshToken(refreshToken)
            .revoked(false)
            .expiry(expiry)
            .build();
    return refreshTokenRepo.save(refreshTokenEntity);
  }

  private AccessToken saveUserAccessToken(User userInfoEntity, String accessToken, int expiry, String refreshTokenId) {
    var accessTokenEntity = AccessToken
            .builder()
            .user(userInfoEntity)
            .accessToken(accessToken)
            .revoked(false)
            .expiry(expiry)
            .refreshTokenId(refreshTokenId)
            .build();
    return accessTokenRepository.save(accessTokenEntity);
  }

  private Cookie creatRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
    Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setSecure(true);
    refreshTokenCookie.setMaxAge(JwtTokenGenerator.REFRESH_TOKEN_EXPIRY); // in seconds
    response.addCookie(refreshTokenCookie);
    return refreshTokenCookie;
  }

  public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {
    log.info("Inside getAccessTokenUsingRefreshToken method");
    if (!authorizationHeader.startsWith(TokenType.Bearer.name())) {
      return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
    }

    final String refreshToken = authorizationHeader.substring(7);

    //Find refreshToken from database and should not be revoked : Same thing can be done through filter.
    var refreshTokenEntity = refreshTokenRepo
            .findByRefreshToken(refreshToken)
            .filter(tokens -> !tokens.isRevoked())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));
    log.info("refreshTokenEntity: " + refreshTokenEntity);
    User userInfoEntity = refreshTokenEntity.getUser();
    refreshTokenEntity.setRevoked(Boolean.TRUE);
    refreshTokenRepo.save(refreshTokenEntity);
    log.info("refreshTokenEntity set to revoked :" + refreshTokenEntity.isRevoked());
    //Now create the Authentication object
    Authentication authentication = createAuthenticationObject(userInfoEntity);

    //Use the authentication object to generate new accessToken as the Authentication object that we will have may
    // not contain correct role.
    String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
    String refreshToken1 = jwtTokenGenerator.generateRefreshToken(authentication);

    //Let's save the refreshToken as well
    RefreshToken refreshToken1Entity =
            saveUserRefreshToken(userInfoEntity, refreshToken1, JwtTokenGenerator.REFRESH_TOKEN_EXPIRY);
    //Let's save the accessToken as well
    saveUserAccessToken(userInfoEntity, accessToken, JwtTokenGenerator.ACCESS_TOKEN_EXPIRY,
            refreshToken1Entity.getId());

    return AuthResponseDto
            .builder()
            .accessToken(accessToken)
            .accessTokenExpiry(JwtTokenGenerator.ACCESS_TOKEN_EXPIRY)
            .userName(userInfoEntity.getUserName())
            .tokenType(TokenType.Bearer)
            .refreshToken(refreshToken1)
            .build();
  }

  public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,
                                      HttpServletResponse httpServletResponse) {
    try {
      log.info("[AuthService:registerUser]User Registration Started with :::{}", userRegistrationDto);

      Optional<User> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
      if (user.isPresent()) {
        throw new Exception("User Already Exist");
      }

      User userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
      Authentication authentication = createAuthenticationObject(userDetailsEntity);

      // Generate a JWT token
      String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
      String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

      User savedUserDetails = userInfoRepo.save(userDetailsEntity);
      RefreshToken refreshToken1Entity =
              saveUserRefreshToken(userDetailsEntity, refreshToken, JwtTokenGenerator.REFRESH_TOKEN_EXPIRY);
      //Let's save the accessToken as well
      saveUserAccessToken(savedUserDetails, accessToken, JwtTokenGenerator.ACCESS_TOKEN_EXPIRY,
              refreshToken1Entity.getId());
      creatRefreshTokenCookie(httpServletResponse, refreshToken);

      log.info("[AuthService:registerUser] User:{} Successfully registered", savedUserDetails.getUserName());
      return AuthResponseDto
              .builder()
              .accessToken(accessToken)
              .accessTokenExpiry(JwtTokenGenerator.ACCESS_TOKEN_EXPIRY)
              .userName(savedUserDetails.getUserName())
              .tokenType(TokenType.Bearer)
              .refreshToken(refreshToken)
              .build();


    } catch (Exception e) {
      log.error("[AuthService:registerUser]Exception while registering the user due to :" + e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }


}
