package com.korit.springboot_security.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRole {
    private int userRoleId;
    private int userId;
    private int roleId;

    private Role role;
}