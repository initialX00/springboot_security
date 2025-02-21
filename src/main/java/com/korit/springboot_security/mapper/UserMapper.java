package com.korit.springboot_security.mapper;

import com.korit.springboot_security.entity.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    int insert(User user);
    User selectByUsername(String username);
    User selectById(int userId);
    List<User> selectAll();
    int updateUserById(User user);
    int deleteById(int userId);
}