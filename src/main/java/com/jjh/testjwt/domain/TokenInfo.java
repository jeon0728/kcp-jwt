package com.jjh.testjwt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Builder
@Data
@AllArgsConstructor
public class TokenInfo {

    private String grantType;
    private String accessToken;
    private String refreshToken;
    private long accessTokenExpiresIn;
    private long refreshTokenExpiresIn;

}