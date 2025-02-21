package com.korit.springboot_security.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil { //provider or utill로 이름 짓는다
    private Key key;
    private Long  accessTokenExpire;
    private Long  refreshTokenExpire;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        accessTokenExpire = 1000l * 60 * 60 ; //AccessToken 적정 시간 10분 ~ 1시간 (보안이 중요할수록 짧게)
        refreshTokenExpire = 1000l * 60 * 60 * 24 * 7; //RefreshToken 적정시간 7일 ~ 90일(보안이 중요할수록 짧게)
    }

    public String generateToken(String userId, String username, boolean isRefreshToken) {
        return Jwts.builder()
                .setId(userId)
                .setSubject(username)
                .setExpiration(
                        new Date(System.currentTimeMillis()
                        + (isRefreshToken ? refreshTokenExpire : accessTokenExpire))
                )
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return claims;
    }
}
