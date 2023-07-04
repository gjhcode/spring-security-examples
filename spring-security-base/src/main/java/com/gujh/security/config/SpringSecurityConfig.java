package com.gujh.security.config;

import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class SpringSecurityConfig {

    @Resource(name = "commonAuthenticationHandler")
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Resource(name = "commonAuthenticationHandler")
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Resource(name = "commonAuthenticationHandler")
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Resource(name = "commonAuthenticationHandler")
    private AccessDeniedHandler accessDeniedHandler;

    @Resource(name = "commonAuthenticationHandler")
    private LogoutSuccessHandler logoutSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/**")
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/login**", "/logout").permitAll()
                        .requestMatchers("*.css", "*.js").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .formLogin(form -> form
                        .loginProcessingUrl("/login/form")
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(authenticationFailureHandler))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .clearAuthentication(true))
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

}
