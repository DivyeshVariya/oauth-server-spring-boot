package io.itpl.auth.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "account")
@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Account {
  @Id
  private String id;
  private String mcc;
  private String mobileNumber;
  private String deviceId; // Active device for single device login
}
