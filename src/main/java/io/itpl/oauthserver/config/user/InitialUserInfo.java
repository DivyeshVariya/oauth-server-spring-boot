package io.itpl.oauthserver.config.user;

import io.itpl.oauthserver.models.User;
import io.itpl.oauthserver.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;


@RequiredArgsConstructor
@Component
@Slf4j
public class InitialUserInfo implements CommandLineRunner {
  private final UserRepo userInfoRepo;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) throws Exception {
    User manager = new User();
    manager.setUserName("Manager");
    manager.setPassword(passwordEncoder.encode("password"));
    manager.setRoles("ROLE_MANAGER");
    manager.setEmailId("manager@manager.com");

    User admin = new User();
    admin.setUserName("Admin");
    admin.setPassword(passwordEncoder.encode("password"));
    admin.setRoles("ROLE_ADMIN");
    admin.setEmailId("admin@admin.com");

    User user = new User();
    user.setUserName("User");
    user.setPassword(passwordEncoder.encode("password"));
    user.setRoles("ROLE_USER");
    user.setEmailId("user@user.com");

    userInfoRepo.saveAll(List.of(manager, admin, user));
  }

}