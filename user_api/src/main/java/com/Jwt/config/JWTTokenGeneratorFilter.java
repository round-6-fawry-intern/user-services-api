package com.Jwt.config;

import com.Jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JWTTokenGeneratorFilter extends OncePerRequestFilter {
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (SecurityContextHolder.getContext().getAuthentication() != null
                && (authHeader == null || !authHeader.startsWith("Bearer "))
        ) {
            System.out.println("ok");
            String email = SecurityContextHolder.getContext().getAuthentication().getName();
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            String jwt = jwtService.generateToken(userDetails);
            response.setHeader("Authorization", "Bearer " + jwt);
        }

        filterChain.doFilter(request, response);
    }
}
