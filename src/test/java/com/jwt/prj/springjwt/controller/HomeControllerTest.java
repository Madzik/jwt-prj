package com.jwt.prj.springjwt.controller;

import com.jwt.prj.springjwt.configuration.SecurityConfiguration;
import com.jwt.prj.springjwt.service.TokenService;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({HomeController.class, AuthController.class})
@Import({SecurityConfiguration.class, TokenService.class})
class HomeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @SneakyThrows
    public void unauthorizedUser_shouldForbid() {
        this.mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }

}