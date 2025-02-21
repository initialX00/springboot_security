package com.korit.springboot_security.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.korit.springboot_security.dto.request.redis.ReqRedisDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/redis")
public class RedisController {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @PostMapping("/json")
    public ResponseEntity<String> json(@RequestBody ReqRedisDto reqRedisDto) throws JsonProcessingException {
        String json = objectMapper.writeValueAsString(reqRedisDto);
        redisTemplate.opsForValue().set(reqRedisDto.getKey(), json, Duration.ofMinutes(5));
        return ResponseEntity.ok().build();
    }

    @GetMapping("/json/{key}")
    public ResponseEntity<?> jsonGet(@PathVariable String key) throws JsonProcessingException {
        String value = redisTemplate.opsForValue().get(key).toString();
        ReqRedisDto reqRedisDto = objectMapper.readValue(value, ReqRedisDto.class);
        return ResponseEntity.ok(reqRedisDto);
    }

    @PostMapping("/{key}/{value}")
    public ResponseEntity<?> set(@PathVariable String key, @PathVariable String value) {
        // user:1:name, "김준일"
        redisTemplate.opsForValue().set("user:" + key + ":name", value, Duration.ofSeconds(60)); //문자열 저장
        return ResponseEntity.ok().build();
    }

    @GetMapping("/{key}")
    public ResponseEntity<?> get(@PathVariable String key) {
        String value = redisTemplate.opsForValue().get(key).toString();
        return ResponseEntity.ok(value);
    }
}
