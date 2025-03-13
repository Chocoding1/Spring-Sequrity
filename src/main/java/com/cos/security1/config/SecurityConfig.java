package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록되도록 한다.
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http    .authorizeHttpRequests(auth -> auth
                                .requestMatchers("/user/**").authenticated() // /user로 들어오는 경우에는 로그인을 해야 접근 가능
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") // /manager로 들어오는 경우에는 로그인 + ADMIN이나 MANAGER 권한이 있어야 접근 가능
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN") // /admin으로 들어오는 경우에는 로그인 + ADMIN 권한이 있어야 접근 가능
                                .anyRequest().permitAll()) // 이외의 접근은 모두 허용)
                .formLogin(formLogin -> // 권한이 필요하다고 설정한 /user/**, /manager/**, /admin/**에 대해 /login으로 이동하도록 설정
                        formLogin.loginPage("/login"));

        return http.build();
    }
}
