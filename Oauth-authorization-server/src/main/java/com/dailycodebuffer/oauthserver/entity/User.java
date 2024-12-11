package com.dailycodebuffer.oauthserver.entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
@Data
public class User {

    @Id
    private Long id;
    private String firstName;
    private String lastName;
    private String email;

    private String password;

    private String role;
    private boolean enabled = false;
}
