package com.martin.springboot.security.authserver.auth.server.auth.filters;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martin.springboot.security.authserver.auth.server.models.User;
import com.martin.springboot.security.authserver.auth.server.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.martin.springboot.security.authserver.auth.server.auth.TokenConfig.*;


public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
  public AuthenticationManager authenticationManager;
  private UserRepository userRepository;

  public JwtAuthenticationFilter(AuthenticationManager authenticationManager, UserRepository userRepository){
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {
    User user = null;
    String username = null;
    String password = null;

    try {
      user = new ObjectMapper().readValue(request.getInputStream(), User.class);
      username = user.getEmail();
      password = user.getPassword();

    } catch (StreamReadException e) {
      e.printStackTrace();
    } catch (DatabindException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }

    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
    return authenticationManager.authenticate(authToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    String username = ((org.springframework.security.core.userdetails.User ) authResult.getPrincipal()).getUsername();
    
    // Long userId = userRepository.getUserId(username);
    User user = userRepository.getUserByEmail(username).orElseThrow();
    Long userId = user.getId();
    Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

    boolean isAdmin = roles.stream().anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
    Claims claims = Jwts.claims();
    claims.put("authorities", new ObjectMapper().writeValueAsString(roles));
    claims.put("isAdmin", isAdmin);
    claims.put("userId", userId);
    String token = Jwts.builder()
      .setClaims(claims)
      .setSubject(username)
      .signWith(SECRET_KEY)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + 7200000))
      .compact();
    response.addHeader(HEADER_AUTHORIZATION, PREFIX_TOKEN + token);
    Map<String,Object> body = new HashMap<>();
    body.put("token", token);
    body.put("message", String.format("Hola %s, has iniciado sesion con exito", username));
    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(200);
    response.setContentType("application/json");
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      final AuthenticationException failed) throws IOException, ServletException {
    
    Map<String, Object> body = new HashMap<>();
    body.put("message", "Error en la autenticacion username o password incorrecto");
    body.put("error", failed.getMessage());

    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(401);
    response.setContentType("application/json");
  }

}
