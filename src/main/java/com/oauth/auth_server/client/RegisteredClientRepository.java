package com.oauth.auth_server.client;

import org.springframework.lang.Nullable;

/**
 * 인가 서버에 등록된 Client 정보를 저장하고 조회하는 인터페이스
 */
public interface RegisteredClientRepository {

    /**
     * Saves the registered client.
     *
     * <p>
     * IMPORTANT: Sensitive information should be encoded externally from the
     * implementation, e.g. {@link RegisteredClient#getClientSecret()}
     * @param registeredClient the {@link RegisteredClient}
     */
    void save(RegisteredClient registeredClient);

    /**
     * Returns the registered client identified by the provided {@code id}, or
     * {@code null} if not found.
     * @param id the registration identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    @Nullable
    RegisteredClient findById(String id);

    /**
     * Returns the registered client identified by the provided {@code clientId}, or
     * {@code null} if not found.
     * @param clientId the client identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    @Nullable
    RegisteredClient findByClientId(String clientId);

}