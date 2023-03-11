package co.develhope.LoginSystemSpring.auth.services;

import co.develhope.LoginSystemSpring.auth.entities.RequestPasswordDTO;
import co.develhope.LoginSystemSpring.auth.entities.RestorePasswordDTO;
import co.develhope.LoginSystemSpring.notifications.services.MailNotificationService;
import co.develhope.LoginSystemSpring.users.entities.User;
import co.develhope.LoginSystemSpring.users.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
@Service
public class PasswordService{

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MailNotificationService mailNotificationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User request(RequestPasswordDTO requestPasswordDTO) throws Exception {
        User userFromDB = userRepository.findByEmail(requestPasswordDTO.getEmail());
        if (userFromDB == null) throw new Exception("User is null");
        userFromDB.setPasswordResetCode(UUID.randomUUID().toString());
        mailNotificationService.sendPasswordResetMail(userFromDB);
        return userRepository.save(userFromDB);
    }

    public User restore(RestorePasswordDTO restorePasswordDTO) throws Exception {
        User userFromDB = userRepository.findByPasswordResetCode(restorePasswordDTO.getResetPasswordCode());
        if (userFromDB == null) throw new Exception("User is null");
        userFromDB.setPassword(passwordEncoder.encode(restorePasswordDTO.getNewPassword()));
        userFromDB.setPasswordResetCode(null);
        userFromDB.setIsActive(true);
        userFromDB.setActivationCode(null);
        return userRepository.save(userFromDB);
    }
}
