package com.gujh.security.config;

import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CommonAuthenticationHandler implements AuthenticationSuccessHandler,
        AuthenticationFailureHandler,
        AuthenticationEntryPoint,
        AccessDeniedHandler,
        LogoutSuccessHandler {

    @Resource
    private JsonMapper jsonMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("code", 200);
        result.put("message", "登录成功");
        result.put("data", authentication);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("code", 500);
        result.put("message", "登录失败[" + exception.getMessage() + "]");
        result.put("data", null);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("code", 500);
        result.put("message", "认证失败[" + authException.getMessage() + "]");
        result.put("data", null);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("code", 500);
        result.put("message", "权限不足[" + accessDeniedException.getMessage() + "]");
        result.put("data", null);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("code", 200);
        result.put("message", "登出成功");
        result.put("data", authentication);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }
}
