package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록되도록 한다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
/**
 * @EnableMethodSecurity
 * @EnableGlobalMethodSecurity 대체
 * securedEnabled = true : @Secured 어노테이션 활성화
 * prePostEnabled = true : @PreAuthorize, @PostAuthorize 어노테이션 활성화
 */
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http
                .authorizeHttpRequests(authorize -> authorize // 권한 인가 설정
                        .requestMatchers("/user/**").authenticated() // /user로 들어오는 경우에는 인증 필요
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") // /manager로 들어오는 경우에는 ADMIN이나 MANAGER 권한 필요
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN") // /admin으로 들어오는 경우에는 ADMIN 권한 필요
                        .anyRequest().permitAll() // 이외의 접근은 모두 허용)
                )
                .formLogin(formLogin -> formLogin // 폼 로그인 설정
                        .loginPage("/loginForm") // 권한이 필요하다고 설정한 /user/**, /manager/**, /admin/**에 대해 /loginForm url로 이동하도록 설정
                        /**
                         * /login이 호출되면 security가 낚아채서 대신 로그인 프로세스 진행
                         * 이렇게 하면 컨트롤러에 /login api를 안 만들어도 된다. security가 알아서 로그인을 진행해준다.
                         */
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/") // 로그인 성공 시, redirect url 설정
                );
        return http.build();
    }
}
