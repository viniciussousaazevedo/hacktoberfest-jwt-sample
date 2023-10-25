package com.jwt.sample.DTO;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class UserRegistrationDTO {

    private String name;

    private String username;

    private NewPasswordDTO newPasswordDTO;

}
