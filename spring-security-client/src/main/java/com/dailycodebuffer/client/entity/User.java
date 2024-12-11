package com.dailycodebuffer.client.entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
@Data
public class User {

    @Id
    private String id;
    private String firstName;
    private String lastName;
    private String email;

//    @Column(length = 60)
    private String password;

    private String role;
    private boolean enabled = false;
}
