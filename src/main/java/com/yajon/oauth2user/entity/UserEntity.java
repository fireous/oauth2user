package com.yajon.oauth2user.entity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user")
@JsonIgnoreProperties({"enabled", "accountNonExpired", "accountNonLocked", "credentialsNonExpired", "hibernateLazyInitializer", "handler"})
public class UserEntity implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private String name;

    @JsonIgnore
    @OneToMany(
        mappedBy = "user", 
        fetch=FetchType.LAZY, 
        cascade = CascadeType.ALL, 
        orphanRemoval = false
    )
    List<MessageEntity> messages;
    
    public UserEntity(Map<String, String> registerDataMap) {
        this.username = registerDataMap.get("username");
        this.password = registerDataMap.get("password");
        this.name = registerDataMap.get("name");
    }

    public UserEntity(String username, String password) {
        this.username = username;
        this.password = password;
        this.name = username;
    }

    @JsonIgnore
    @Transient
    private List<GrantedAuthority> authorities = null;
    
    public List<GrantedAuthority> getAuthorities(){
        if (this.authorities == null){
            this.authorities = new ArrayList<GrantedAuthority>();
            this.authorities.add(new SimpleGrantedAuthority("read"));
            this.authorities.add(new SimpleGrantedAuthority("user"));
        }

        return this.authorities;
    }

    @Override
    public boolean isAccountNonExpired() { 
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
