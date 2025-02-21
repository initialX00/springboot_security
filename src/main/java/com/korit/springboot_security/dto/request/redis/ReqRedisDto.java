package com.korit.springboot_security.dto.request.redis;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

@Data
@Schema(description = "레디스 스터디를 위한 DTO") //dto들 앞으로는 schema 사용
public class ReqRedisDto {
    @Schema(description = "키값", example = "key1")
    private String key;
    @Schema(description = "데이터값", example = "value1")
    private String value;
    @Schema(description = "데이터값 리스트", example = "[1, 2, 3, 4]")
    private List<Integer> values;
}
