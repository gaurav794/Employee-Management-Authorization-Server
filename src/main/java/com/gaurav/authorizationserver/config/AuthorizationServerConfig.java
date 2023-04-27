package com.gaurav.authorizationserver.config;

import com.gaurav.authorizationserver.config.keys.JwkKeys;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    private final CORSCustomizer corsCustomizer;
    private final PasswordEncoder passwordEncoder;

    public AuthorizationServerConfig(CORSCustomizer corsCustomizer, PasswordEncoder passwordEncoder) {
        this.corsCustomizer = corsCustomizer;
        this.passwordEncoder = passwordEncoder;
    }

    //Add default security
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // Take this http config into consideration first
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        //Allow requests from different clients meaning from other than auth server
        corsCustomizer.corsCustomizer(http);
        //Requests handled in SecurityConfig
        return http.formLogin(Customizer.withDefaults()).build();
    }

    //Registering Angular Client Details
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        //Build client
        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                //Password Must be encoded otherwise you get error 401 unauthorized
                .clientSecret(passwordEncoder.encode("secret"))
                .scope(OidcScopes.OPENID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                //After successfully authentication the client
                .redirectUri("http://127.0.0.1:4200/authorized")
                .tokenSettings
                        (TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofHours(10))
                                .refreshTokenTimeToLive(Duration.ofHours(10)).build())
                .clientSettings
                        (ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        //Store client into repo
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    //Add server settings
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:8080").build();
    }

    //Generate Keys
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = JwkKeys.generateRSAkey();
        JWKSet set = new JWKSet(rsaKey);
        return (j, sc) -> j.select(set);
    }
}
