package io.itpl.auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

  @GetMapping("/secured")
  public String securedEndpoint() {
    return "This is a secured resource!";
  }
}

