package org.aj.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;
import java.util.List;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception { // @formatter:off
//        http
//                .requestMatchers(r -> r.antMatchers("/**"))
//                .authorizeRequests(a -> a
//                        .anyRequest().authenticated()
//                )
//                .formLogin(f -> f.permitAll())
//                .logout(l -> l.permitAll())
//                .csrf(c -> c.disable());

        http
                .authorizeRequests()
                .mvcMatchers("/.well-known/jwks.json").permitAll()
                .anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));

    } // @formatter:on

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }



    @Bean
    @Override
    public UserDetailsService userDetailsService() {
//		return new InMemoryUserDetailsManager(
//				User.withDefaultPasswordEncoder()
//					.username("admin")
//					.password("admin")
//                        .passwordEncoder(p->passwordEncoder().encode(p))
//					.roles("USER")
//					.build());


        UserDetailsService a = username -> {
            List<SimpleGrantedAuthority> grantedAuthorities = Arrays.asList(new SimpleGrantedAuthority("ADMIN"));
            return new User("admin", new BCryptPasswordEncoder().encode("admin"), grantedAuthorities);
        };  // (2)
        return a;
    }
}
