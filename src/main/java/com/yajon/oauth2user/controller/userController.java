package com.yajon.oauth2user.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import com.yajon.oauth2user.entity.UserEntity;
import com.yajon.oauth2user.service.impl.UserServiceImpl;

@RestController
public class userController {

    @Autowired
    private UserServiceImpl service;
    
    @PostMapping("/rest/user")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public @ResponseBody Object registerUser(
        @RequestBody Map<String, String> registerDataMap,
        Authentication authentication
    ) throws Exception {
        service.registerUser(registerDataMap);
        
		JwtAuthenticationToken customCodeGrantAuthentication = (JwtAuthenticationToken) authentication;
        return customCodeGrantAuthentication.getPrincipal();

    }
    
    @PatchMapping("/rest/user/{id}")
    @PreAuthorize("hasAuthority('SCOPE_user')")
    public @ResponseBody Object updateUser(
        @PathVariable(value="id") Long id,
        @RequestBody Map<String, String> updateMap,
        Authentication authentication
    ) throws Exception {
        UserEntity user = service.updateUser(id, updateMap);
        return user;
    }
}
