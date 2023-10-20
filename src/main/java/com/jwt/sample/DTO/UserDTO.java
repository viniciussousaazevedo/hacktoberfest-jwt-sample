package com.jwt.sample.DTO;

import com.jwt.sample.enums.UserRole;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class UserDTO {

    private String name;

    private String username;

    private UserRole userRole;

}
