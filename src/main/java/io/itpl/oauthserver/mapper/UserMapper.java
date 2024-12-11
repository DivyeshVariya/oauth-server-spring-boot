package io.itpl.oauthserver.mapper;

import io.itpl.oauthserver.dto.UserRegistrationDto;
import io.itpl.oauthserver.models.User;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public abstract class UserMapper {
  @Autowired
  private PasswordEncoder passwordEncoder;

  public User convertToEntity(UserRegistrationDto userRegistrationDto) {
    User userInfoEntity = new User();
    userInfoEntity.setUserName(userRegistrationDto.userName());
    userInfoEntity.setEmailId(userRegistrationDto.userEmail());
    userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
    userInfoEntity.setRoles(userRegistrationDto.userRole());
    userInfoEntity.setPassword(passwordEncoder.encode(userRegistrationDto.userPassword()));
    return userInfoEntity;
  }
}
