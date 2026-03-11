package com.oauth.auth_server.resourceserver;

public record ResourceServerUserProfile(
        String username,
        String name,
        String email,
        String role,
        String department,
        String phoneNumber
) {
}
