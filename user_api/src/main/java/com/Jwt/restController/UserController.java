package com.Jwt.restController;

import com.Jwt.dto.ChangePassword;
import com.Jwt.entity.Role;
import com.Jwt.entity.User;
import com.Jwt.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;

    @PatchMapping("/active/{id}")
    public boolean changeActivity(@PathVariable Long id) {
        User user = userRepo.findById(id).orElse(null);
        if (user == null) {
            return false;
        }
        user.setActive(!user.isActive());
        userRepo.save(user);
        return true;
    }

    @PatchMapping("/Convert-to-admin/{id}")
    public boolean convertToAdmin(@PathVariable Long id) {
        User user = userRepo.findById(id).orElse(null);
        if (user == null) {
            return false;
        }
        user.setRole(Role.ADMIN);
        userRepo.save(user);
        return true;
    }

    @PatchMapping("/reset-password/{id}")
    public boolean resetPassword(@PathVariable Long id, @RequestBody ChangePassword changePassword) {
        User user = userRepo.findById(id).orElse(null);
        if (user != null && passwordEncoder.matches(changePassword.getOldPassword(), user.getPassword())) {
            user.setPassword(passwordEncoder.encode(changePassword.getNewPassword()));
            userRepo.save(user);
            return true;
        }
        return false;
    }

}
