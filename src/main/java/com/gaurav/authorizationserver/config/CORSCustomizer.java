package com.gaurav.authorizationserver.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Component
public class CORSCustomizer {

    public void corsCustomizer(HttpSecurity http) throws Exception {
        http.cors(c ->
                {
                    CorsConfigurationSource source = s ->
                    {
                        CorsConfiguration corsConfiguration = new CorsConfiguration();
                        corsConfiguration.setAllowCredentials(true);
                        corsConfiguration.setAllowedOrigins(List.of("https://employee-management-pi-nine.vercel.app"));
                        corsConfiguration.setAllowedHeaders(List.of("*"));
                        corsConfiguration.setAllowedMethods(List.of("*"));
                        return corsConfiguration;
                    };
                    c.configurationSource(source);
                }
        );
    }
}
