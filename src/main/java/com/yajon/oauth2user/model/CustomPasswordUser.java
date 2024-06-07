package com.yajon.oauth2user.model;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public record CustomPasswordUser(Long id, String username, Collection<GrantedAuthority> authorities) {

}
