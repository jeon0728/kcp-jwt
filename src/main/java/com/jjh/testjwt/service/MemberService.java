package com.jjh.testjwt.service;

import com.jjh.testjwt.JwtTokenProvider;
import com.jjh.testjwt.domain.TokenInfo;
import com.jjh.testjwt.domain.TokenRequestDto;
import com.jjh.testjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.concurrent.TimeUnit;


@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    @Transactional
    public TokenInfo login(String memberId, String password) {
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        //4. redis에 RT 저장
        redisTemplate.opsForValue()
                .set("RefreshToken:" + authentication.getName(), tokenInfo.getRefreshToken(),
                        tokenInfo.getRefreshTokenExpiresIn() - new Date().getTime(), TimeUnit.MILLISECONDS);

        return tokenInfo;
    }

    @Transactional(rollbackFor = Exception.class)
    public ResponseEntity<?> reissue(TokenRequestDto tokenRequestDto) {
        if (!jwtTokenProvider.validateToken(tokenRequestDto.getRefreshToken())) {
            return ResponseEntity.badRequest().body("Refresh Token이 유효하지 않습니다.");
            //throw new IllegalStateException("Refresh Token이 유효하지 않습니다.");
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDto.getAccessToken());

        //Redis에서 Refresh Token 가져오기
        String refreshToken = (String) redisTemplate.opsForValue().get("RefreshToken:" + authentication.getName());
        if(!refreshToken.equals(tokenRequestDto.getRefreshToken())) {
            return ResponseEntity.badRequest().body("토큰의 유저 정보가 일치하지 않습니다.");
        }

        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);
        //새로 발급된 RefreshToken Redis에 저장
        redisTemplate.opsForValue()
                .set("RefreshToken:" + authentication.getName(), tokenInfo.getRefreshToken(),
                        tokenInfo.getRefreshTokenExpiresIn(), TimeUnit.MILLISECONDS);

        return ResponseEntity.ok(tokenInfo);
    }
}