package io.itpl.oauthserver.config.user;

import io.itpl.oauthserver.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class UserInfoManagerConfig implements UserDetailsService {

  private final UserRepo userInfoRepo;

  @Override
  public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
    return userInfoRepo
            .findByEmailId(emailId)
            .map(UserInfoConfig::new)
            .orElseThrow(() -> new UsernameNotFoundException("UserEmail: " + emailId + " does not exist"));
  }
}
