package com.yajon.oauth2user.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.yajon.oauth2user.entity.UserEntity;

public interface UserService extends UserDetailsService {
    public void registerUser(UserEntity user) throws Exception;
    public void registerUser(Map<String, String> registerDataMap) throws Exception;
    public UserEntity updateUser(Long id, Map<String, String> updateMap) throws Exception;
}
