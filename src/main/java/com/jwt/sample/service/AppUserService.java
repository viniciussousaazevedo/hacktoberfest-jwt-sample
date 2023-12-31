package com.jwt.sample.service;



import com.jwt.sample.DTO.UserDTO;
import com.jwt.sample.DTO.NewPasswordDTO;
import com.jwt.sample.DTO.UserRegistrationDTO;
import com.jwt.sample.model.AppUser;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AppUserService extends UserDetailsService {

    AppUser getUser(String username);

    AppUser registerUser(UserRegistrationDTO userRegistrationDTO);

    void saveUser(AppUser appUser);

    void checkPasswordConfirmation(String password, String passwordConfirmation);

    AppUser updateUser(UserDTO user);

    String forgotPassword(String username);

    String changePassword(String token, NewPasswordDTO newPasswordDTO);

}
