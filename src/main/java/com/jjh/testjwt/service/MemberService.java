package com.jjh.testjwt.service;

import com.fasterxml.jackson.databind.util.JSONPObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jjh.testjwt.JwtTokenProvider;
import com.jjh.testjwt.domain.TokenInfo;
import com.jjh.testjwt.domain.TokenRequestDto;
import com.jjh.testjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.json.JSONParser;
import org.json.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.AnonymousAuthenticationWebFilter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Date;
import java.util.HashMap;
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
                .set(tokenInfo.getAccessToken(), tokenInfo.getUserInfo().toString(),
                        tokenInfo.getAllExpiresIn(), TimeUnit.MILLISECONDS);

//        redisTemplate.opsForValue()
//                .set("RefreshToken:" + authentication.getName(), tokenInfo.getRefreshToken(),
//                        tokenInfo.getRefreshTokenExpiresIn(), TimeUnit.MILLISECONDS);

        return tokenInfo;
    }

    @Transactional(rollbackFor = Exception.class)
    public ResponseEntity<?> reissue(TokenRequestDto tokenRequestDto) {
        Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDto.getAccessToken());

        //Redis에서 json object 가져오기
        String strJson = (String) redisTemplate.opsForValue().get(tokenRequestDto.getAccessToken());

        if (strJson == null) {
            return ResponseEntity.badRequest().body("해당 토큰의 정보가 존재하지 않습니다.");
        }

        JsonParser parser = new JsonParser();
        JsonElement element = parser.parse(strJson);

        long issueTime = Long.parseLong(element.getAsJsonObject().get("issueTime").toString());
        String userIp = element.getAsJsonObject().get("userIp").toString();
        String readOnly = element.getAsJsonObject().get("readOnly").toString();

        long now = (new Date()).getTime();
        //Date issue = new Date(issueTime);
        Date current = new Date(now);

        // Date -> 밀리세컨즈
        long issueTimeMil1 = issueTime;
        long currentTimeMil2 = current.getTime();

        // 비교
        long diff = currentTimeMil2 - issueTimeMil1;
        long diffMin = diff / (1000 * 60);

        //토큰 전체 시간이 15분이 지나지 않은 경우 json object readOnly 값 true 로 변경
        if(diffMin < 15 && readOnly.equals("N")) {
            //redis 수정
            JSONObject userInfo = new JSONObject();
            userInfo.put("userId", authentication.getName());
            userInfo.put("userIp", userIp);
            userInfo.put("issueTime", issueTime);
            userInfo.put("readOnly", "Y");
            //기존 AccessToken, json object Redis에 다시 저장
            redisTemplate.opsForValue()
                    .set(tokenRequestDto.getAccessToken(), userInfo.toString(),
                            current.getTime(), TimeUnit.MILLISECONDS);
        } else {}
        //15분과 상관없이 AccessToken, json object 재발급
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);
        //새로 발급된 AccessToken, json object Redis에 저장
        redisTemplate.opsForValue()
                .set(tokenInfo.getAccessToken(), tokenInfo.getUserInfo().toString(),
                        tokenInfo.getAllExpiresIn(), TimeUnit.MILLISECONDS);
        return ResponseEntity.ok(tokenInfo);
    }

    public HashMap<String, Object> callApi(String url, String id) {
        HashMap<String, Object> result = new HashMap<String, Object>();

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders header = new HttpHeaders();
            header.setContentType(MediaType.APPLICATION_JSON);
            HashMap<String, String> body = new HashMap<String, String>();
            body.put("id", id);
            body.put("pwd", "o");
            //HttpEntity<?> entity = new HttpEntity<>(header);
            HttpEntity<?> entity = new HttpEntity<>(body, header);
            UriComponents uri = UriComponentsBuilder.fromHttpUrl(url).build();

            //ResponseEntity<?> returnMap = restTemplate.exchange(uri.toString(), HttpMethod.GET, entity, Object.class);
            ResponseEntity<?> returnMap = restTemplate.exchange(uri.toString(), HttpMethod.POST, entity, Object.class);

            result.put("statusCode", returnMap.getStatusCodeValue()); //http status code를 확인
            result.put("header", returnMap.getHeaders()); //헤더 정보 확인
            result.put("body", returnMap.getBody()); //실제 데이터 정보 확인

            //에러처리해야댐
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            result.put("statusCode", e.getRawStatusCode());
            result.put("body", e.getStatusText());
            System.out.println("error");
            System.out.println(e.toString());

            return result;
        }
        catch (Exception e) {
            result.put("statusCode", "9999");
            result.put("body", "excpetion오류");
            System.out.println(e.toString());

            return result;

        }

        return result;
    }
}