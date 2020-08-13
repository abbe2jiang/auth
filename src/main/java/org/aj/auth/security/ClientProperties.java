package org.aj.auth.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Data
@Configuration
@ConfigurationProperties(prefix = "aj.auth")
public class ClientProperties {

    @PostConstruct
    public void validate() {
        this.getClient().values().forEach(this::validateClient);
    }

    private void validateClient(Client client) {
        if (!StringUtils.hasText(client.getClientId())) {
            throw new IllegalStateException("Client id must not be empty.");
        }
    }

    private final Map<String, Client> client = new HashMap<>();

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
        private Set<String> scopes;
        private Set<String> redirectUris;
    }
}
