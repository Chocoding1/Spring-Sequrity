package com.cos.security1.auth;

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인이 완료가 되면 시큐리티 session을 만들어준다.
 * 세션 공간은 HttpSession과 동일한데, 시큐리티가 그 안에 시큐리티 세션 공간을 따로 분리한다.
 * 'SecurityContextHolder'라는 key값에 세션 정보를 저장한다.
 * 이 때 시큐리티가 가지고 있는 세션에 들어갈 수 있는 오브젝트는 정해져 있다. => Authentication 타입의 객체만 들어갈 수 있다.
 * 그리고 Authentication 안에는 User 정보가 들어가 있어야 된다.
 * 이 User 오브젝트의 타입도 정해져 있다. => UserDetails 타입의 객체만 들어갈 수 있다.
 * 즉 시큐리티 세션에는 Authentication 타입만 저장될 수 있고, Authentication 안에는 UserDetails 타입만 저장될 수 있다.
 * Security Session <= Type(Authentication) <= Type(UserDetails)
 *
 * UserDetails 만들었으면, Authentication도 만들어야 한다.
 */

public class PrincipalDetails implements UserDetails { // UserDetails를 구현함으로써, PrincipalDetails 타입은 Authentication 안에 저장될 수 있다.

    private User user; // 콤포지션 : 기존 클래스를 확장하는 대신, 새로운 클래스를 만들고 private 필드로 기존 클래스의 인스턴스를 참조하는 방법을 통해 기능을 확장시키는 것

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 User의 권한을 리턴하는 곳 (권한은 유저의 role을 뜻한다.)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        // user의 role은 String 타입이기 때문에 GrantedAuthority 타입으로 변환해야 한다.
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료됐는지 체크
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겼는지 체크
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정의 비밀번호가 유효기간이 지났는지 체크
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화되어 있는지 체크
    @Override
    public boolean isEnabled() {
        /**
         * 언제 이런 것들을 사용하냐
         * ex) 우리 서비스에 회원이 1년동안 로그인을 안 하면, 휴면 계정으로 전환하고자 할 때 사용
         * 위처럼 서비스를 만든다면, User 엔티티에 lastLoginDate같은 필드를 넣어서
         * 현재 날짜 = user.getLastLoginDate > 1년
         * 이면 false를 반환하도록 로직을 추가하면 된다.
         */
        return true;
    }

}
