package com.oauth.auth_server.test.repository;


import com.oauth.auth_server.test.entity.OauthClients;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OauthClientsRepository extends JpaRepository<OauthClients, String> {
    @Query("""
    select c
    from OauthClients as c
    where c.clientId = :clientId and c.active = true
    """)
    Optional<OauthClients> findActiveClient(@Param("clientId") String clientId);
}