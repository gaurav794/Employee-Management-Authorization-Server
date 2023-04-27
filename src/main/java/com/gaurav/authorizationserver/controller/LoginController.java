package com.gaurav.authorizationserver.controller;

import com.gaurav.authorizationserver.controller.util.RestResponseStatus;
import com.gaurav.authorizationserver.model.UserRole;
import com.gaurav.authorizationserver.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;


@Controller
public class LoginController {

    private final UserRepository userRepository;
    private final PasswordEncoder bcryptPasswordEncoder;

    public LoginController(UserRepository userRepository, PasswordEncoder bcryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bcryptPasswordEncoder = bcryptPasswordEncoder;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("user", new UserRole());
        return "register";
    }

    @PostMapping("/register")
    public String userRegistration(@ModelAttribute("user") UserRole user) {
        //Encoding the password
        String rawPassword = user.getPassword();
        String encodedPassword = bcryptPasswordEncoder.encode(rawPassword);
        UserRole newUser = new UserRole(user.getUser_name(), user.getEmail_id(), user.getPhone_number(), encodedPassword, "user", new Date());
        //save user
        try {
            userRepository.save(newUser);
        }
        catch (DataIntegrityViolationException e) {
            return "redirect:register?exists";
        }
        catch (Exception e) {
            return "redirect:register?error";
        }

       return "redirect:register?registered";
    }

    @GetMapping("/confirm_logout")
    public String logout() {
        return "confirm_logout";
    }

}
