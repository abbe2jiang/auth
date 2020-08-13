package org.aj.auth;

import lombok.extern.slf4j.Slf4j;
import org.aj.auth.security.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j
@SpringBootApplication
public class AuthApplication {

    public static void main(String[] args) {
        log.info("------------------------- app starting... ----------------------");
        SpringApplication.run(AuthApplication.class, args);
        log.info("------------------------- app started. -------------------------");
    }
}
