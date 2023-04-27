package com.gaurav.authorizationserver.service;

import com.gaurav.authorizationserver.model.UserRole;
import com.gaurav.authorizationserver.repository.UserRepository;
import com.gaurav.authorizationserver.service.util.LoginUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService
{

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
    {
        UserRole user = userRepository.findByEmail_id(username);

        if(user == null) return null;

        return new LoginUserDetails(user);
    }
}
