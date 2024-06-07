package com.yajon.oauth2user.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.yajon.oauth2user.service.MessageService;

@RestController
@RequestMapping("/rest/message")
public class messageController {

    @Autowired
    private MessageService service;

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_user')")
    public Object createMessage(
        @RequestBody Map<String, String> messageMap,
        Authentication authentication
    ) throws Exception {
        Long userId = this.getUserId(authentication);
        String message = messageMap.get("content");
        return service.createMessage(message, userId);
    }
    
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_user')")
    public Object listMessage(
        Authentication authentication
    ) throws Exception {
        Long userId = this.getUserId(authentication);
        return service.listMessage(userId);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_user')")
    public Object showMessage(
        @PathVariable(value="id") Long id,
        Authentication authentication
    ) throws Exception {
        Long userId = this.getUserId(authentication);
        return service.showMessage(id, userId);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_user')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteMessage(
        @PathVariable(value="id") Long id,
        Authentication authentication
    ) throws Exception {
        Long userId = this.getUserId(authentication);
        service.deleteMessage(id, userId);
    }
    
    private Long getUserId(Authentication authentication) {
		JwtAuthenticationToken customCodeGrantAuthentication = (JwtAuthenticationToken) authentication;
        
        return (Long)customCodeGrantAuthentication.getTokenAttributes().get("id");
    }
}
