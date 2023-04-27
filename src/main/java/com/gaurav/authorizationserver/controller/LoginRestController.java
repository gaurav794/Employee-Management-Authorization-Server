//package com.gaurav.authorizationserver.controller;
//
//import com.gaurav.authorizationserver.controller.util.RestResponseStatus;
//import com.gaurav.authorizationserver.model.UserRole;
//import com.gaurav.authorizationserver.service.CustomAuthenticationProvider;
//import com.gaurav.authorizationserver.service.CustomUserDetailsService;
//import com.gaurav.authorizationserver.service.util.LoginUserDetails;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.web.bind.annotation.*;
//
//@RestController
//public class LoginRestController {
//
//    @ResponseBody
//    @PostMapping("/api/register")
//    public ResponseEntity register(@RequestBody UserRole user)
//    {
//        return new ResponseEntity(successMessage(),HttpStatus.OK);
//    }
//
//    private RestResponseStatus successMessage() {
//        return new RestResponseStatus("SUCCESS", "Valid User");
//    }
//
//    private RestResponseStatus failureMessage() {
//        return new RestResponseStatus("FAILURE", "Invalid Credentials. Please try again.");
//    }
//
//    //in case of maintenance
//    private RestResponseStatus errorMessage() {
//        return new RestResponseStatus("INTERNAL_SERVER_ERROR",
//                "Internal server error, please try again after sometime. If this problem continues, contact IT Department.");
//    }
//
//}
