package com.loginservice.login.service;

import com.loginservice.login.entity.Users;
import com.loginservice.login.repository.UsersRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

@Service
public class UsersServiceImpl implements UsersService {

    private static final Logger logger = LogManager.getLogger(UsersServiceImpl.class);

    @Autowired
    UsersRepository usersRepository;

    PasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public void addOrUpdate(Users user) {
        usersRepository.save(user);
    }

    @Override
    public Users getUserById(UUID id) {
        return usersRepository.findById(id).get();
    }

    @Override
    public boolean isPassword (Users user, String enteredPassword) {
        String hashedPassword = user.getPassword();
        return checkPass(enteredPassword, hashedPassword);
    }

    @Override
    public Users findUserByEmail (String email) {
        return usersRepository.findUsersByEmail(email);
    }

    private boolean checkPass(String enteredPassword, String hashedPassword) {
        if (encoder.matches(enteredPassword, hashedPassword))
            return true;
        else {
            logger.error("Wrong Password -> " + enteredPassword);
            return false;
        }
    }

}
