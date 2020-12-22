package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.demo.security.ApplicationUserRole.*;

// 2020.12.22

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    // ctrl+o 단축키를 통해 override 할 수 있는 메소드 목록을 볼 수 있음

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //
        http
                // http 요청의, 인증방법으로, antMatchers에 해당하는 패턴을 가진 uri는, 모두 허가해주고
                // 나머지 모든요청은, 인증받아야한다, 그리고, 방식은 httpBasic으로 한다
                // 매우 중요한 csrf, 잘 공부해놔야함
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                // role 기반 안티매칭
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // permission 기반 안티매칭 방법1
                // antMatchers안의 요청 방식과, uri 패턴은 hasAuthority 안의 permission을 가진 사용자만 접근할 수 있다
//                .antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.name())

                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // 이건 role 기반, antMatchers 안의 uri 패턴은 hasAnyRole안의 role을 가진 모든 사용자가 접근 가능
                .antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINIE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }
    // 이 방법을 하게 되면 브라우저에서 팝업으로 아이디, 비번을 입력받는 식으로 인증을함
    // 단점은 로그아웃할수있는 방법이 없음, 모든 요청에 대해서 비밀번호를 헤더에 넣어서 서버로 요청하기 때문


    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
//        User.UserBuilder annaSmithUser = User.builder()
//                .username("annasmith")
//                .password("password")
//                .roles("STUDENT")
//                .build();
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINIE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
