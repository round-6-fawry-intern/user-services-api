package com.Jwt.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePassword {
    private String newPassword;
    private String oldPassword;
}
