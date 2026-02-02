package com.oauth.auth_server.repository;


import com.oauth.auth_server.entity.OauthClients;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthClientsRepository extends JpaRepository<OauthClients, String> {
}