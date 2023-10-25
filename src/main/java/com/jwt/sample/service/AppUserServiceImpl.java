package com.jwt.sample.service;

import com.jwt.sample.DTO.UserDTO;
import com.jwt.sample.DTO.UserRegistrationDTO;
import com.jwt.sample.enums.UserRole;
import com.jwt.sample.exception.ApiRequestException;
import com.jwt.sample.model.AppUser;
import com.jwt.sample.repository.AppUserRepository;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@AllArgsConstructor
public class AppUserServiceImpl implements AppUserService {

    private static final String USER_NOT_FOUND = "Usuário não encontrado";
    private static final String USERNAME_ALREADY_TAKEN = "e-mail %s já se encontra cadastrado";
    private static final String UNMATCHED_PASSWORDS = "A senha informada não coincide com a confirmação de senha";


    AppUserRepository appUserRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private ModelMapper modelMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException(USER_NOT_FOUND));
    }

    @Override
    public AppUser getUser(String username) {
        return this.appUserRepository.findByUsername(username)
                .orElseThrow(() -> new ApiRequestException(USER_NOT_FOUND));
    }

    @Override
    public AppUser registerUser(UserRegistrationDTO userRegistrationDTO) {
        this.checkUsername(userRegistrationDTO.getUsername());
        this.checkPasswordConfirmation(userRegistrationDTO.getPassword(), userRegistrationDTO.getPasswordConfirmation());

        userRegistrationDTO.setPassword(bCryptPasswordEncoder.encode(userRegistrationDTO.getPassword()));

        AppUser appUser = this.modelMapper.map(userRegistrationDTO, AppUser.class);
        appUser.setUserRole(UserRole.DEFAULT);

        this.saveUser(appUser);
        return appUser;
    }

    @Override
    public void saveUser(AppUser appUser) {
        this.appUserRepository.save(appUser);
    }

    private void checkUsername(String username) {
        if (this.appUserRepository.findByUsername(username).isPresent()) {
            throw new ApiRequestException(String.format(USERNAME_ALREADY_TAKEN, username));
        }
    }

    @Override
    public void checkPasswordConfirmation(String password, String passwordConfirmation) {
        if (!password.equals(passwordConfirmation)) {
            throw new ApiRequestException(UNMATCHED_PASSWORDS);
        }
    }

    @Override
    public AppUser updateUser(UserDTO userDTO) {
        AppUser appUser = getUser(userDTO.getUsername());
        appUser.setName(userDTO.getName());
        appUser.setUserRole(userDTO.getUserRole());

        return this.appUserRepository.save(appUser);
    }
}
