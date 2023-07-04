package com.gujh.security.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class SecurityUserService implements UserDetailsService {

    private static final Map<String, UserDetails> USER_CACHE_MAP = new HashMap<>();

    static {
        UserDetails user1 = User.withUsername("gujh").password("{noop}test").authorities("create").build();
        USER_CACHE_MAP.put("gujh", user1);
        UserDetails user2 = User.withUsername("xiaogu").password("{noop}test").authorities("delete").build();
        USER_CACHE_MAP.put("xiaogu", user2);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = Optional.ofNullable(USER_CACHE_MAP.get(username))
                .orElseThrow(() -> new UsernameNotFoundException(username));
        return User.withUsername(userDetails.getUsername())
                .password(userDetails.getPassword())
                .authorities(userDetails.getAuthorities())
                .build();
    }
}
