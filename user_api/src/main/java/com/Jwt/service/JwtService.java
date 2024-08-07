package com.Jwt.service;

import com.Jwt.entity.Token;
import com.Jwt.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    private static final String SECRET_KEY = "27665f646271574e3b337d5a7d5a3d4d6951275a583e6f7b7363354c55";
    private final TokenRepository tokenRepository;

    // ToDo: extract claims
    public String extractUserEmail(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extraxtAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extraxtAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKet())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

//    ToDo: validation
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserEmail(token);
        Token myToken = tokenRepository.findByToken(token).orElseThrow();
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token) && !myToken.isExpired();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    // todo: Generate claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKet(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKet() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
