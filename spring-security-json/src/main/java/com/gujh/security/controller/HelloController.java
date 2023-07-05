package com.gujh.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping("/1")
    public String hello1() {
        return "hello1";
    }

    @GetMapping("/2")
    public String hello2() {
        return "hello2";
    }

}
