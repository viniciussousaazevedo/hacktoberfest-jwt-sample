package com.jwt.sample.service;


import com.jwt.sample.DTO.UserRegistrationDTO;
import com.jwt.sample.model.AppUser;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AppUserService extends UserDetailsService {

    AppUser getUser(String username);

    AppUser registerUser(UserRegistrationDTO userRegistrationDTO);

    void saveUser(AppUser appUser);

    void checkPasswordConfirmation(String password, String passwordConfirmation);
}
