package com.oauth.auth_server.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthDebugController {

    @GetMapping("/oauth2/authorize")
    public String authorizeDebug(@AuthenticationPrincipal UserDetails user) {
        return "OK - logged in as: " + user.getUsername();
    }
}
