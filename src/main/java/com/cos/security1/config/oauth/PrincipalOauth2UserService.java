package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    /**
     * 구글로부터 받은 userRequest 데이터에 대한 후처리하는 함수
     * 함수 종료 시, @AuthenticationPrincipal 어노테이션 만들어진다.
     */
    /**
     * 단순히 OAuth2User를 반환할 거면 loadUser 함수를 오버라이딩할 필요가 없다.
     * 오버라이딩하지 않아도 알아서 OAuth2User를 반환한다.
     * 그러나 오버라이딩한 이유는 OAuth2User를 반환하는 것이 아니라 PrincipalDetails를 반환하려고 하기 때문이다.
     * 또한 회원가입 프로세스도 추가했기 때문에 오버라이딩을 한 것이다.
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        System.out.println("getAccessToken : " + userRequest.getAccessToken());
        /**
         * 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> 코드 리턴(OAuth-Client 라이브러리가 받아줌) -> 코드를 통해 Access Token 요청
         * 요청해서 받은 Access Token값까지가 userRequest 정보이다.
         * 이 userRequest 정보를 가지고 구글로부터 회원 프로필을 받아야 하는데, 그 때 사용하는 함수가 아래의 loadUser() 메서드이다.
         * 로그인 완료 -> userRequest 정보 -> loadUser() 호출 -> 구글로부터 회원 프로필 반환
         */
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("getAttributes  : " + oAuth2User.getAttributes()); // 이 Attribute 정보들을 가지고 User 엔티티에 매핑할 예정

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        } else {
            log.info("구글, 페이스북, 네이버 로그인만 지원합니다.");
        }

        // 회원가입 진행
        String provider = oAuth2UserInfo.getProvider(); // google or facebook
        /**
         * providerId값 추출 시 key값
         * google : sub
         * facebook : id
         */
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; // google_216543218921321
        String password = bCryptPasswordEncoder.encode("개발왕");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        // 중복 회원가입 체크
        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(userEntity);
        } else {
            log.info("이전에 로그인한 적이 있습니다. 마지막 로그인 : " + provider);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes()); // PrincipalDetails가 OAuth2User을 상속받았으니 반환 가능
        /**
         * 유저 객체와 속성들을 담아서 리턴하면 이 OAuth2User 객체는 Authentication 내부에 들어가게 된다. Authentication(OAuth2User)
         * 그리고 그 Authentication 객체는 시큐리티 session에 들어가게 된다. 시큐리티 session(Authentication(OAuth2User))
         * 즉 PrincipalDetails를 리턴하면 자동으로 시큐리티 세션이 초기화되는 것이다.
         */
    }
}
