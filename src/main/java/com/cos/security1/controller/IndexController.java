package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 일반 로그인 시 Authentication 객체에는 UserDetails 타입의 객체가 들어간다.
     * 컨트롤러에서 Authentication 객체에 접근하는 두 가지 방법 (DI 활용)
     * 1. Authentication 객체 사용
     * 2. @AuthenticationPrincipal 어노테이션 사용 (UserDetails 객체를 사용할 수 있는데, PrincipalDetails가 UserDetails를 상속받았기 때문에 사용 가능)
     */
    @ResponseBody
    @GetMapping("/test/login")
    public String testLogin(Authentication authentication,
                            @AuthenticationPrincipal PrincipalDetails userDetails) {
        System.out.println("/test/login ================");
        // Authentication 객체 사용해서 User 객체 추출
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : " + principalDetails.getUser());

        // @AuthenticationPrincipal 어노테이션 사용해서 User 객체 추출
        System.out.println("userDetails : " + userDetails.getUser());

        return "세션 정보 확인하기";
    }

    /**
     * OAuth2.0 로그인 시 Authentication 객체에는 OAuth2User 타입의 객체가 들어간다.
     * 컨트롤러에서 Authentication 객체에 접근하는 두 가지 방법 (DI 활용)
     * 1. Authentication 객체 사용
     * 2. @AuthenticationPrincipal 어노테이션 사용 (OAuth2User 객체를 사용 가능)
     */
    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String testOAuthLogin(Authentication authentication,
                                 @AuthenticationPrincipal OAuth2User oAuth) {
        System.out.println("/test/oauth/login ================");
        // Authentication 객체 사용해서 User 객체 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + oAuth2User.getAttributes());

        System.out.println("oauth2User : " + oAuth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    /**
     * 위의 방법은 사용자가 일반 로그인할 때와 OAuth 로그인할 때를 둘 다 생각해서 만들어야 하기 때문에 번거롭다.
     * 이 번거로움을 해결하기 위해 PrincipalDetails가 UserDetails 뿐만 아니라 OAuth2User도 상속받게 했다. (Authentication 객체 안에는 두 클래스 다 들어갈 수 있다.)
     * 그에 맞춰 PrincipalOauth2UserService도 만들고, 여기에서도 마지막에 User 객체를 PrincipalDetails 객체로 감싸서 반환한다.
     * 이 번거로움을 해결한 결과는 /user API에서 확인
     */

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    /**
     * 일반 로그인을 해도 PrincipalDetails로 받을 수 있고,
     * OAuth 로그인을 해도 PrincipalDetails로 받을 수 있다.
     * @AuthenticationPrincipal 어노테이션은 loadUserByUsername 또는 loadUser 함수가 종료되면 생성된다.
     */
    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails.getUser());
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
