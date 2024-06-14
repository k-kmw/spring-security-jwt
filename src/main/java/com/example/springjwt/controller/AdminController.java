package com.example.springjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;

public class AdminController {

    @GetMapping("/admin")
    public String adminP() {

        return "Admin Controller";
    }
}
