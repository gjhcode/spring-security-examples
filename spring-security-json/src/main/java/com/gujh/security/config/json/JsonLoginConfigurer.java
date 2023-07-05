/*
 * ------------------------------------------------------------------
 * Copyright © 2017 Hangzhou DtDream Technology Co.,Lt d. All rights reserved.
 * ------------------------------------------------------------------
 *       Product:
 *   Module Name:
 *  Date Created: 2023/7/5
 *   Description:
 * ------------------------------------------------------------------
 * Modification History
 * DATE            Name           Description
 * ------------------------------------------------------------------
 * 2023/7/5    小谷 g2038          created
 * ------------------------------------------------------------------
 */
package com.gujh.security.config.json;

import com.gujh.security.config.CommonAuthenticationHandler;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JsonLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, JsonLoginConfigurer<H>, JsonUsernamePasswordAuthenticationFilter> {

    private SavedRequestAwareAuthenticationSuccessHandler defaultSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;


    public JsonLoginConfigurer() {
        super(new JsonUsernamePasswordAuthenticationFilter(), "/login/json");
        usernameParameter("username");
        passwordParameter("password");
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    public void configure(H http) throws Exception {
        PortMapper portMapper = http.getSharedObject(PortMapper.class);
        if (portMapper != null) {
            ((LoginUrlAuthenticationEntryPoint)getAuthenticationEntryPoint()).setPortMapper(portMapper);
        }
        RequestCache requestCache = http.getSharedObject(RequestCache.class);
        if (requestCache != null) {
            defaultSuccessHandler.setRequestCache(requestCache);
        }
        getAuthenticationFilter().setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        getAuthenticationFilter().setAuthenticationSuccessHandler(new CommonAuthenticationHandler());
        getAuthenticationFilter().setAuthenticationFailureHandler(new CommonAuthenticationHandler());
        if (this.authenticationDetailsSource != null) {
            getAuthenticationFilter().setAuthenticationDetailsSource(this.authenticationDetailsSource);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }
        SecurityContextConfigurer securityContextConfigurer = http.getConfigurer(SecurityContextConfigurer.class);
        if (securityContextConfigurer != null) {
            SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
            if (securityContextRepository == null) {
                securityContextRepository = new DelegatingSecurityContextRepository(
                        new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
            }
            getAuthenticationFilter().setSecurityContextRepository(securityContextRepository);
        }
        getAuthenticationFilter().setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        JsonUsernamePasswordAuthenticationFilter filter = postProcess(getAuthenticationFilter());
        http.addFilterAfter(filter, UsernamePasswordAuthenticationFilter.class);
    }

    public static JsonLoginConfigurer<HttpSecurity> jsonLogin() {
        return new JsonLoginConfigurer<>();
    }

    public JsonLoginConfigurer<H> usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    public JsonLoginConfigurer<H> passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }
}
