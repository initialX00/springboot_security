package com.korit.springboot_security.service;

import com.korit.springboot_security.dto.request.auth.ReqSigninDto;
import com.korit.springboot_security.dto.response.RespAuthDto;
import com.korit.springboot_security.entity.User;
import com.korit.springboot_security.repository.UserRepository;
import com.korit.springboot_security.security.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private RedisTokenService redisTokenService;

    public RespAuthDto login(ReqSigninDto reqSigninDto) {
        User foudUser = userRepository.findByUsername(reqSigninDto.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("사용자 정보를 확인하세요"));

        if(!passwordEncoder.matches(reqSigninDto.getPassword(), foudUser.getPassword())) {
            throw new BadCredentialsException("사용자 정보를 확인하세요");
        }

        String accessToken = jwtUtil
                .generateToken(
                        Integer.toString(foudUser.getUserId()),
                        foudUser.getUsername(),
                        false);
        String refreshToken = jwtUtil
                .generateToken(
                        Integer.toString(foudUser.getUserId()),
                        foudUser.getUsername(),
                        true);

        redisTokenService.setAccess(reqSigninDto.getUsername(), accessToken, Duration.ofMinutes(60));
        redisTokenService.setRefresh(reqSigninDto.getUsername(), accessToken, Duration.ofDays(7));

        return RespAuthDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public RespAuthDto refresh(String refreshToken) {
        Claims claims = jwtUtil.parseToken(refreshToken);
        if(claims == null) {
            return null;
        }
        String username = claims.getSubject();
        String userId = claims.getId();
        String redisRefresh = redisTokenService.getRefreshToken(username);
        if(redisRefresh == null || !redisRefresh.equals(refreshToken)) {
            return null;
        }
        String newAccessToken = jwtUtil.generateToken(userId,username, false);
        return RespAuthDto.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
