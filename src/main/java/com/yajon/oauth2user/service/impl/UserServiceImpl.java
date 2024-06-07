package com.yajon.oauth2user.service.impl;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.yajon.oauth2user.entity.UserEntity;
import com.yajon.oauth2user.repository.UserRepository;
import com.yajon.oauth2user.service.UserService;

import jakarta.transaction.Transactional;


@Transactional
@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        return user;
    }

    @Override
    public void registerUser(Map<String, String> registerDataMap) throws Exception {
        UserEntity user = new UserEntity(registerDataMap);

        userRepository.save(user);
    }
    
    @Override
    public void registerUser(UserEntity user) throws Exception {
        userRepository.save(user);
    }

    @Override
    public UserEntity updateUser(Long id, Map<String, String> updateMap) throws Exception {
        UserEntity user = userRepository.getReferenceById(id);
        String username = updateMap.get("username");
        String password = updateMap.get("password");
        String name = updateMap.get("name");

        if (username != null && !username.equals("")) {
            user.setUsername(username);
        }
        if (password != null && !password.equals("")) {
            user.setPassword(password);
        }
        if (name != null && !name.equals("")) {
            user.setName(name);
        }
        userRepository.save(user);

        return user;
    }


}