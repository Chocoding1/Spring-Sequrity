package com.cos.security1.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

@Entity
@Builder
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@ToString
public class User {

    @Id
    @GeneratedValue
    private Long id;

    private String username;
    private String password;
    private String email;
    private String role; // ROLE_USER, ROLE_MANAGER, ROLE_ADMIM => 꼭 ROLE_~ 형태로 저장해야 security가 작동한다.

    private String provider; // 일반적인 사용자인지 Oauth 사용자인지 구분하기 위한 필드
    private String providerId;

    @CreationTimestamp
    private Timestamp createDate;


}
