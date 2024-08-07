package com.Jwt.service;

import com.Jwt.dto.AuthenticationRequest;
import com.Jwt.dto.AuthenticationResponse;
import com.Jwt.dto.RegisterRequest;
import com.Jwt.entity.Role;
import com.Jwt.entity.Token;
import com.Jwt.entity.User;
import com.Jwt.repository.TokenRepository;
import com.Jwt.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepo.existsByEmail(request.getEmail())) {
            throw new RuntimeException("this email already exist");
        }
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .isActive(true)
                .build();
        userRepo.save(user);
        String jwtToken = jwtService.generateToken(user);
        Token token = new Token(jwtToken);
        user.add(token);
        userRepo.save(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
//        todo: if the email or password incorrect then exception will throws
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        User user = userRepo.findByEmail(request.getEmail()).orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        Token token = new Token(jwtToken);
        user.add(token);
        userRepo.save(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

}
