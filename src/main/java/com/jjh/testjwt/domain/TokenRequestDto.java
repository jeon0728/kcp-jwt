package com.jjh.testjwt.domain;

import lombok.Data;

@Data
public class TokenRequestDto {
    private String memberId;
    private String accessToken;
    private String refreshToken;
}
