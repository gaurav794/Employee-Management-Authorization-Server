package com.gaurav.authorizationserver.config;


import com.gaurav.authorizationserver.service.CustomAuthenticationProvider;
import com.gaurav.authorizationserver.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.*;

@Configuration
public class WebSecurityConfig {
    private final CORSCustomizer corsCustomizer;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;
    private final CustomAuthenticationProvider authenticationProvider;

    public WebSecurityConfig(CORSCustomizer corsCustomizer, PasswordEncoder passwordEncoder, CustomUserDetailsService userDetailsService, CustomAuthenticationProvider authenticationProvider) {
        this.corsCustomizer = corsCustomizer;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //Allow requests from different clients meaning from other than auth server
        corsCustomizer.corsCustomizer(http);

//      TODO: Later Find the way to implement custom login page

        return http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/register").permitAll()
                .antMatchers(HttpMethod.GET,"/register?**").permitAll()
                .antMatchers(HttpMethod.POST,"/register").permitAll()
                .anyRequest().authenticated().and()
                .formLogin(form ->
                        form.loginPage("/login")
                                .permitAll())
                .rememberMe().and()
                .logout().logoutSuccessUrl("https://employee-management-pi-nine.vercel.app/login").permitAll().and()
                .build();
    }

    @Autowired
    public void authManager(AuthenticationManagerBuilder auth) throws Exception {

        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }


}
