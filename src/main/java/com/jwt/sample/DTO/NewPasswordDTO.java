package com.jwt.sample.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class NewPasswordDTO {

    public String password;
    public String passwordConfirmation;

}
