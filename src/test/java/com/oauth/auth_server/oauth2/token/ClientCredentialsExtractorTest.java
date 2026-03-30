package com.oauth.auth_server.oauth2.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClientCredentialsExtractorTest {

    private ClientCredentialsExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new ClientCredentialsExtractor();
    }

    @Test
    void Basic_헤더에서_클라이언트_자격증명을_추출한다() {
        String encoded = Base64.getEncoder()
                .encodeToString("client1:secret1".getBytes(StandardCharsets.UTF_8));
        String header = "Basic " + encoded;

        Optional<ClientCredentials> result = extractor.extract(header, null, null);

        assertThat(result).isPresent();
        assertThat(result.get().clientId()).isEqualTo("client1");
        assertThat(result.get().clientSecret()).isEqualTo("secret1");
    }

    @Test
    void form_파라미터에서_클라이언트_자격증명을_추출한다() {
        Optional<ClientCredentials> result = extractor.extract(null, "client1", "secret1");

        assertThat(result).isPresent();
        assertThat(result.get().clientId()).isEqualTo("client1");
        assertThat(result.get().clientSecret()).isEqualTo("secret1");
    }

    @Test
    void Basic_헤더가_있으면_form_파라미터보다_우선한다() {
        String encoded = Base64.getEncoder()
                .encodeToString("headerClient:headerSecret".getBytes(StandardCharsets.UTF_8));
        String header = "Basic " + encoded;

        Optional<ClientCredentials> result = extractor.extract(header, "formClient", "formSecret");

        assertThat(result).isPresent();
        assertThat(result.get().clientId()).isEqualTo("headerClient");
    }

    @Test
    void Basic_헤더와_form_파라미터_모두_없으면_빈_Optional을_반환한다() {
        Optional<ClientCredentials> result = extractor.extract(null, null, null);

        assertThat(result).isEmpty();
    }

    @Test
    void Basic_헤더_포맷이_잘못되면_빈_Optional을_반환한다() {
        String invalidEncoded = Base64.getEncoder()
                .encodeToString("noclientidsecret".getBytes(StandardCharsets.UTF_8));
        String header = "Basic " + invalidEncoded;

        Optional<ClientCredentials> result = extractor.extract(header, null, null);

        assertThat(result).isEmpty();
    }

    @Test
    void Basic_헤더_인코딩이_유효하지_않으면_빈_Optional을_반환한다() {
        Optional<ClientCredentials> result = extractor.extract("Basic !!!invalid!!!", null, null);

        assertThat(result).isEmpty();
    }

    @Test
    void form_파라미터에서_clientId만_있으면_빈_Optional을_반환한다() {
        Optional<ClientCredentials> result = extractor.extract(null, "client1", null);

        assertThat(result).isEmpty();
    }

    @Test
    void form_파라미터에서_clientSecret만_있으면_빈_Optional을_반환한다() {
        Optional<ClientCredentials> result = extractor.extract(null, null, "secret1");

        assertThat(result).isEmpty();
    }
}
