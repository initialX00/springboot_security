package com.korit.springboot_security.security.principal;


import com.korit.springboot_security.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

@Getter
@AllArgsConstructor
public class PrincipalUser implements UserDetails {
    private User user;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getUserRoles()
                .stream()
                .map(userRole -> new SimpleGrantedAuthority(userRole.getRole().getRoleName()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getIsAccountNonExpired() == 1; //계정 사용기간 만료 여부
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getIsAccountNonLocked() == 1; //계정 잠금 여부
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getIsCredentialsNonExpired() == 1; //계정 인가 여부
    }

    @Override
    public boolean isEnabled() {
        return user.getIsEnabled() == 1; //계정 활성 여부
    }
}
