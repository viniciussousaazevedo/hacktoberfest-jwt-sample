package com.jwt.sample.controller;


import com.jwt.sample.DTO.NewPasswordDTO;
import com.jwt.sample.DTO.UserDTO;
import com.jwt.sample.DTO.UserRegistrationDTO;
import com.jwt.sample.model.AppUser;
import com.jwt.sample.service.AppUserService;
import com.jwt.sample.service.TokenManagerService;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping(path = "/api/usuario")
@AllArgsConstructor
public class AppUserController {

    AppUserService appUserService;

    ModelMapper modelMapper;

    TokenManagerService tokenDecoder;

    @PostMapping("/cadastro")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO userRegistrationDTO) {

        AppUser appUser = this.appUserService.registerUser(userRegistrationDTO);
        UserDTO userDTO = this.modelMapper.map(appUser, UserDTO.class);

        return new ResponseEntity<>(userDTO, HttpStatus.CREATED);
    }
  
   @GetMapping
    public ResponseEntity<?> whoAmI() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AppUser user = this.appUserService.getUser((String) authentication.getPrincipal());
        return ResponseEntity.ok(user);
    }

    @GetMapping("esqueci-senha")
    public ResponseEntity<?> forgotPassword(@RequestBody String username) {
        return ResponseEntity.ok(this.appUserService.forgotPassword(username));
    }

    @PutMapping("/atualizar")
    public ResponseEntity<?> updateUser(@RequestBody UserDTO user) {
        return ResponseEntity.ok(this.modelMapper.map(appUserService.updateUser(user), UserDTO.class));
  
    @PostMapping("/esqueci-senha/{token}")
    public ResponseEntity<?> changePassword(@PathVariable String token, @RequestBody NewPasswordDTO newPasswordDTO) {
        return ResponseEntity.ok(appUserService.changePassword(token, newPasswordDTO));

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        this.tokenDecoder.refreshToken(request, response);
    }
}
