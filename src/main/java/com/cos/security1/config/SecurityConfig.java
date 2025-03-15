package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
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
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

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
                )
                .oauth2Login(oauth2 -> oauth2 // oauth2.0 로그인 설정
                        .loginPage("/loginForm") // 구글 로그인 완료된 이후 후처리 필요 => 구글 로그인이 완료되면, (엑세스 토큰 + 사용자 프로필 정보)를 한 번에 받는다.
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(principalOauth2UserService)) // 후처리하는 service 등록
                );
        return http.build();
    }
}
