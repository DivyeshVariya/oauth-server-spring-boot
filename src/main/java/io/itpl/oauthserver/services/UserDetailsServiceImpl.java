//package io.itpl.oauthserver.services;
//
//import io.itpl.oauthserver.models.User;
////import io.itpl.oauthserver.repository.UserRepository;
//import io.itpl.oauthserver.repository.UserRepository;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.List;
//@Slf4j
//@Service
//public class UserDetailsServiceImpl implements UserDetailsService {
//
//  private final UserRepository userRepository;
//  public static List<User> users = new ArrayList<>();
////  private final PasswordEncoder passwordEncoder;
//
//  public UserDetailsServiceImpl(
//          UserRepository userRepository
////          ,
////          PasswordEncoder passwordEncoder
//  ) {
//    this.userRepository = userRepository;
////    this.passwordEncoder = passwordEncoder;
//  }
//
//  @Bean
//  public PasswordEncoder passwordEncoder() {
//    return new BCryptPasswordEncoder(11);
//  }
//
//
//  @Override
//  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//    log.trace("Inside loadUserByUsername method");
//    User user = userRepository.findByUsername(username);
////    User user = users.stream().filter(usr->usr.getUsername().equals(username)).findFirst().get();
//    if (user == null) {
//      throw new UsernameNotFoundException("User not found");
//    }
//    log.trace("Input : "+username +" User: " + user.getUsername());
//    return org.springframework.security.core.userdetails.User
//            .withUsername(user.getUsername())
//            .password(user.getPassword())
//            .roles(user.getRoles())
//            .build();
//  }
//
//  public User registerUser(User userModel) {
//    User user = new User();
//    user.setUsername(userModel.getUsername());
//    user.setRoles("USER");
//    user.setPassword(passwordEncoder().encode(userModel.getPassword()));
//
//    userRepository.save(user);
//    return user;
//  }
//}
//
//
