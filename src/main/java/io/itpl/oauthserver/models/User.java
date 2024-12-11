package io.itpl.oauthserver.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document
public class User {
  @Id
  private String id;

  private String userName;

  private String emailId;

  private String mobileNumber;

  private String roles;

  private String password;

  private List<RefreshToken> refreshTokens;
}
