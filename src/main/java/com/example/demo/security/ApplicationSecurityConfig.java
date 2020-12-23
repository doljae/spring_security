package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

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
                // csrf 에 대한 이해를 해야함
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                // role 기반 안티매칭
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // permission 기반 안티매칭 방법1
                // antMatchers안의 요청 방식과, uri 패턴은 hasAuthority 안의 permission을 가진 사용자만 접근할 수 있다
//                .antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.name())
                // 그리고 순서가 매우 중요한데, antMatchers의 순서에 따라서 통과 되지 말아야할게 통과되는 경우도 있음
                // 즉 이 방식은 약간 문제가 있고, 실제론 다른 방식으로 구현하는게 일반적이라고한다(using annotation_
                // Mapping Method에 ANNOTATION을 달아서 처리
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // 이건 role 기반, antMatchers 안의 uri 패턴은 hasAnyRole안의 role을 가진 모든 사용자가 접근 가능
//                .antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINIE.name())
                .anyRequest()
                .authenticated()
                .and()
//                .httpBasic(); // 이건 basic 방식으로 인증하기
                .formLogin()
                // 일반적으로 세션이 연결되면 세션아이디라는 쿠키가 만들어지고,
                // 서버의 in memory에 상주하게 된다. 즉 서버가 재기동하면 메모리가 날아가서 세션아이디 자체가 날아감
                // 즉 사용자에게 할당된 세션아이디가 바뀔수있음, 이런 것을 해결하기 위해 세션아이디를 postgres, redis에 저장해서 해결함
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingVerySecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                // csrf 설정이 되어있다면 반드시 logout을 POST 방식으로 호출해야함
                // get 방식으로도 하고 싶으면 위에 처럼 logoutRequestMatcher를 사용해서 GET방식으로 설정해줘야 됨
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                    .logoutSuccessUrl("/login");
                // loginPage는 login 이라는 경로를 가지고 인증, 인가 상관없이 접근가능하게 하고,
                // 로그인에 성공하면 courses로 리다이렉트 시킴
                // 그리고 rememberMe 기능도 사용하도록 설정
                // rememberMe 쿠키의 validate초를 21일동안으로 설정,
                // rememberMe 쿠키의 값(해시된)을 만들때 사용할 key로 username + somethingVerySecured 문자열을 사용함
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
