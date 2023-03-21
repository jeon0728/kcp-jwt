package com.jjh.testjwt.controller;

import com.jjh.testjwt.domain.MemberLoginRequestDto;
import com.jjh.testjwt.domain.TokenInfo;
import com.jjh.testjwt.domain.TokenRequestDto;
import com.jjh.testjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login")
    public TokenInfo login(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
        TokenInfo tokenInfo = null;
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        HashMap<String, Object> result = memberService.callApi("https://jsonplaceholder.typicode.com/posts");
        if (result.get("statusCode").equals(200)) {
            tokenInfo = memberService.login(memberId, password);
        } else {}

        return tokenInfo;
    }

    @PostMapping("/test")
    public String test() {
        return "success";
    }

    @PostMapping("/reissue")
    public ResponseEntity reissue(@RequestBody TokenRequestDto tokenRequestDto) {
        ResponseEntity responseEntity = memberService.reissue(tokenRequestDto);
        return responseEntity;
    }
}