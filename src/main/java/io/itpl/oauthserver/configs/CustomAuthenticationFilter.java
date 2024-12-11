package io.itpl.oauthserver.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {
    System.out.println("Inside FilterChain for uri " + request);

    System.out.println("inside if for uri " + request.getRequestURI());

    UserDetails userDetails = new User("username", "password", List.of(new SimpleGrantedAuthority("user")));
    System.out.println(userDetails);
    UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
    SecurityContextHolder
            .getContext()
            .setAuthentication(authentication);
    System.out.println(authentication.getPrincipal());
    System.out.println(authentication.isAuthenticated());
    System.out.println("filter done executing");
    filterChain.doFilter(request, response);
  }
}


