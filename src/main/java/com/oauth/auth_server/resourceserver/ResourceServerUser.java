package com.oauth.auth_server.resourceserver;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "resource_server_users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ResourceServerUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(length = 50)
    private String role;

    @Column(length = 50)
    private String department;

    @Column(length = 30)
    private String phoneNumber;

    public ResourceServerUser(
            String username,
            String name,
            String email,
            String role,
            String department,
            String phoneNumber
    ) {
        this.username = username;
        this.name = name;
        this.email = email;
        this.role = role;
        this.department = department;
        this.phoneNumber = phoneNumber;
    }
}
