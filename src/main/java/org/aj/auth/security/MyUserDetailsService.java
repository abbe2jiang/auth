package org.aj.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    BCryptPasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> grantedAuthorities = Arrays.asList(new SimpleGrantedAuthority("ADMIN"));
        return new org.springframework.security.core.userdetails.User("admin", passwordEncoder.encode("admin"), grantedAuthorities); // (2)
    }
}
