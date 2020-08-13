package org.aj.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HomeController {
    @RequestMapping(value = "/", method = RequestMethod.GET)
    @ResponseBody
    public String home() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            log.info("principal={}", authentication.getPrincipal());
            return "hello " + ((UserDetails) authentication.getPrincipal()).getUsername();
        }
        return "hello world";
    }

    @RequestMapping(value = "/hello/{name}", method = RequestMethod.GET)
    @ResponseBody
    public String hello(@PathVariable("name") String name) {
        log.info("hello name={}", name);
        return "hello " + name;
    }
}