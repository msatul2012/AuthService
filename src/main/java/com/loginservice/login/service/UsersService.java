package com.loginservice.login.service;

import com.loginservice.login.entity.Users;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public interface UsersService {

    void addOrUpdate (Users user);

    Users getUserById (UUID id);

    boolean isPassword (Users user, String password);

    Users findUserByEmail (String email);

}
