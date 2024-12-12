package com.jwt.prj.springjwt.controller;

import com.jwt.prj.springjwt.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final TokenService tokenService;

    @PostMapping("/token")
    public String getToken(Authentication authentication) {
        log.info("Token requested for {}.", authentication.getName());
        String token = tokenService.generateToken(authentication);
        log.info("Token {} created.", token);
        return token;
    }
}
