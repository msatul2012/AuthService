package com.loginservice.login.helper;

import com.loginservice.login.controller.UsersController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;

public class EmailConfirmation {

    private static final Logger logger = LogManager.getLogger(EmailConfirmation.class);
    private void createSessionAndSetMessage (Session session, String toEmail, String subject, String body) {
        try
        {
            MimeMessage msg = new MimeMessage(session);
            //set message headers
            msg.addHeader("Content-type", "text/HTML; charset=UTF-8");
            msg.addHeader("format", "flowed");
            msg.addHeader("Content-Transfer-Encoding", "8bit");

            msg.setFrom(new InternetAddress("no_reply@kkw.com", "NoReply-KKW"));

            msg.setReplyTo(InternetAddress.parse("no_reply@kkw.com", false));

            msg.setSubject(subject, "UTF-8");

            msg.setText(body, "UTF-8");

            msg.setSentDate(new Date());

            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail, false));
            logger.info("Message is ready");
            Transport.send(msg);

            logger.info("Email Sent Successfully!!");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendConfirmation (String toEmail, String fromEmail, String fromPassword, String body, String subject) {

        body = "PLEASE CONFIRM -> " + body;

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Authenticator auth = new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(fromEmail, fromPassword);
            }
        };

        Session session = Session.getInstance(props, auth);

        createSessionAndSetMessage(session, toEmail,subject, body);

    }

}
