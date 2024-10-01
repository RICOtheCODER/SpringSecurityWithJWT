package com.Security.SecurityDemo.controller;

import com.Security.SecurityDemo.jwt.JwtUtils;
import com.Security.SecurityDemo.jwt.LoginRequest;
import com.Security.SecurityDemo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils utils;

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndPoint(){
        return "Hello,User !";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndPoint(){
        return "Hello,Admin !";
    }
    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{
            authentication=authenticationManager.authenticate
                    (new UsernamePasswordAuthenticationToken
                            (loginRequest.getUsername(),loginRequest.getPassword()));

        }catch (AuthenticationException e){
            Map<String,Object> map=new HashMap<>();
            map.put("message","Bad Credentials");
            map.put("status",false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails=(UserDetails)authentication.getPrincipal();
        String jwtToken= utils.generateTokenFromUserName(userDetails);
        List<String > roles=userDetails.getAuthorities().stream()
                .map(item->item.getAuthority()).collect(Collectors.toList());
        LoginResponse loginResponse=new LoginResponse(userDetails.getUsername(),roles,jwtToken);
        return ResponseEntity.ok(loginResponse);



    }
}
