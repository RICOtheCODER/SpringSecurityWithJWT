package com.Security.SecurityDemo.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {


    private String username;
    private List<String > roles;
    private String jwtToken;

}
