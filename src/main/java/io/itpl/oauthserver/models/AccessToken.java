package io.itpl.oauthserver.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document
public class AccessToken {
  @Id
  private String id;
  private String accessToken;
  private boolean revoked;
  private User user;
  private int expiry;
  private String refreshTokenId;
}