package co.develhope.LoginSystemSpring.notifications.services;

import co.develhope.LoginSystemSpring.users.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailNotificationService{

    @Autowired
    private JavaMailSender emailSender;

    public void sendActivationMail(User user) {
        SimpleMailMessage sms = new SimpleMailMessage();
        sms.setTo(user.getEmail());
        sms.setFrom("axelfiumano@gmail.com");
        sms.setReplyTo("axelfiumano@gmail.com");
        sms.setSubject("You have signed up to the platform");
        sms.setText("The activation code is: " + user.getActivationCode());
        emailSender.send(sms);
    }

    public void sendPasswordResetMail(User user) {
        SimpleMailMessage sms = new SimpleMailMessage();
        sms.setTo(user.getEmail());
        sms.setFrom("axelfiumano@gmail.com");
        sms.setReplyTo("axelfiumano@gmail.com");
        sms.setSubject("You have signed up to the platform");
        sms.setText("The activation code is: " + user.getPasswordResetCode());
        emailSender.send(sms);
    }
}
