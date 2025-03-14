package com.cos.security1.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Authentication 객체 만들어주는 Service
 * 얘는 언제 발동되냐
 * 시큐리티 설정(SecurityConfig)에서 loginProcessingUrl("/login")을 설정했을 떄,
 * /login 요청이 오면, 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행된다.
 * 이건 그냥 규칙이기 때문에 꼭 UserDetailsService 타입으로 만들어야 한다. 그래야 해당 타입으로 되어있는 loadUserByUsername이 호출된다.
 */

/**
 * 로그인 폼에서 로그인 버튼을 누르면 /login url로 POST 요청이 들어온다. (securityConfig에서 설정)
 * 그럼 시큐리티가 그걸 낚아채고, Bean 컨테이너에서 UserDetailsService 타입의 빈을 찾는다. (여기서는 PrincipalDetailsService)
 * 해당 빈이 있으면 바로 loadUserByUsername 메서드를 호출한다. 이 떄 폼에서 작성된 username을 가져온다.
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 파라미터로 받는 username은 loginForm에서 날아오는 username이기 때문에
     * HTML 폼에서 username을 받는 태그의 name을 꼭 username으로 맞춰줘야 매칭이 된다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 넘어온 username으로 회원이 존재하는지 확인
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            return new PrincipalDetails(userEntity); // principalDetails는 UserDetails를 상속받기 때문에 반환 가능
            /**
             * 유저 객체를 담아서 리턴하면 이 UserDetails 객체는 Authentication 내부에 들어가게 된다. Authentication(UserDetails)
             * 그리고 그 Authentication 객체는 시큐리티 session에 들어가게 된다. 시큐리티 session(Authentication(UserDetails))
             * 즉 PrincipalDetails를 리턴하면 자동으로 시큐리티 세션이 초기화되는 것이다. (loadUserByUsername 메서드가 알아서 다 해주는 것)
             */
        }
        return null;
    }
}
