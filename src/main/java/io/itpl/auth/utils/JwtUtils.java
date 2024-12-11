//package io.itpl.auth.utils;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import org.springframework.stereotype.Component;
//
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//@Component
//public class JwtUtils {
//  private static final String SECRET_KEY = "your-secret-key"; // Use a secure key
//  private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24; // 24 hours
//
//  public String generateToken(String mobileNumber, String deviceId) {
//    Map<String, Object> claims = new HashMap<>();
//    claims.put("mobileNumber", mobileNumber);
//    claims.put("deviceId", deviceId);
//
//    return Jwts
//            .builder()
//            .setClaims(claims)
//            .setIssuedAt(new Date())
////            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
//            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//            .compact();
//  }
//
//  public Claims extractClaims(String token) {
//    return Jwts.parser()
//               .setSigningKey(SECRET_KEY)
//               .parseClaimsJws(token)
//               .getBody();
//  }
//
//  public String extractDeviceId(String token) {
//    return extractClaims(token).get("deviceId", String.class);
//  }
//
//  public boolean isTokenValid(String token, String deviceId) {
//    String tokenDeviceId = extractDeviceId(token);
//    return tokenDeviceId.equals(deviceId) && !isTokenExpired(token);
//  }
//
//  private boolean isTokenExpired(String token) {
//    return extractClaims(token).getExpiration().before(new Date());
//  }
//}
//
