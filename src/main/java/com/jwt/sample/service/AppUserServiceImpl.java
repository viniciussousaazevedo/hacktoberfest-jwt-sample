package com.jwt.sample.service;

import com.jwt.sample.DTO.UserRegistrationDTO;
import com.jwt.sample.enums.UserRole;
import com.jwt.sample.exception.ApiRequestException;
import com.jwt.sample.model.AppUser;
import com.jwt.sample.repository.AppUserRepository;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.UUID;

@Service
@Transactional
@AllArgsConstructor
public class AppUserServiceImpl implements AppUserService {

    private static final String USER_NOT_FOUND = "Usuário não encontrado";
    private static final String USERNAME_ALREADY_TAKEN = "e-mail %s já se encontra cadastrado";
    private static final String UNMATCHED_PASSWORDS = "A senha informada não coincide com a confirmação de senha";
    private static final int MINUTES_FOR_PASS_REC_TOKEN_EXPIRATION = 10;

    private final JavaMailSender emailSender;
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
    public void forgotPassword(String username) {
        AppUser user = this.appUserRepository.findByUsername(username).orElseThrow(() -> new ApiRequestException(USER_NOT_FOUND));

        user.setRecoveryPasswordToken(UUID.randomUUID().toString());
        user.setRecoveryPasswordTokenExpiration(new Date(System.currentTimeMillis() + MINUTES_FOR_PASS_REC_TOKEN_EXPIRATION * 60 * 1000));
        this.saveUser(user);
        this.sendEmail(user);
    }

    private void sendEmail(AppUser user) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(System.getenv("SPRING_MAIL_USER"));
        message.setTo(user.getUsername());
        message.setSubject("Link para ativação de conta");
        message.setText(
                "Segue link para trocar senha: localhost:8080/api/usuario/esqueci-senha/" + user.getRecoveryPasswordToken() + "\n" +
                "Este link irá expirar em " + MINUTES_FOR_PASS_REC_TOKEN_EXPIRATION + " minutos."
        );
        emailSender.send(message);
    }
}
