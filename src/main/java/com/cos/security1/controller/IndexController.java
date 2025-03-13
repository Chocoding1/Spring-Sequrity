package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private static final Logger log = LoggerFactory.getLogger(IndexController.class);

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
//        userRepository.save(user);
        /**
         * 위처럼 그냥 단순히 spring data jpa를 사용해서 회원가입을 진행하면 security로 로그인할 수 없다.
         * 이유는 패스워드가 암호화가 되지 않았기 때문
         */

        /**
         * 암호화 진행
         */
        String rawPassword = user.getPassword();
        // Bean으로 등록된 BCryptPasswordEncoder를 사용해서 인코딩 진행
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        user.setPassword(encPassword);
        userRepository.save(user);

        return "redirect:/loginForm";
    }

    /**
     * @Secured
     * 특정 url에 간단하게 걸 때 사용
     * 하나의 권한만 설정할 때 사용
     * SecurityConfig에서 @EnableMethodSecurity을 설정했기 때문에 사용할 수 있는 것
     */
    @Secured("ROLE_ADMIN")
    @ResponseBody
    @GetMapping("/info")
    public String info() {
        return "개인정보";
    }

    /**
     * @PreAuthorize
     * 특정 url에 간단하게 걸 때 사용
     * 여러 권한을 설정할 때 사용
     * "ROLE_MANGER"만 적으면 안 됨 (hasRole() 메서드 사용)
     */
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @ResponseBody
    @GetMapping("/data")
    public String data() {
        return "데이터 정보";
    }
}
