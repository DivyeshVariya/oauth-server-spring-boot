//package io.itpl.oauthserver.controllers;
//
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//@RequestMapping("/api/resource")
//public class ResourceController {
//
//  @GetMapping("/secured")
//  public String getSecuredData(@AuthenticationPrincipal Jwt jwt) {
//    return "Hello, " + jwt.getSubject() + "! You are accessing a secured resource.";
//  }
//
//  @GetMapping("/public")
//  public String getPublicData() {
//    return "This is a public resource that doesn't require authentication.";
//  }
//}
//
