package com.socialflux.auth.mail;

import com.socialflux.auth.config.AuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class MailConfig {

    private static final Logger log = LoggerFactory.getLogger(MailConfig.class);

    @Bean
    MailService mailService(AuthProperties properties, ObjectProvider<JavaMailSender> sender) {
        if (properties.mail().enabled() && sender.getIfAvailable() != null) {
            JavaMailSender mailSender = sender.getObject();
            String from = properties.mail().from();
            return (to, subject, text) -> {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setFrom(from);
                message.setTo(to);
                message.setSubject(subject);
                message.setText(text);
                mailSender.send(message);
            };
        }
        // Desenvolvimento sem SMTP: o corpo (com o link) só é logado em DEBUG para não vazar tokens em produção.
        return (to, subject, text) -> {
            log.info("E-mail (SMTP desabilitado) para {}: {}", to, subject);
            log.debug("Corpo do e-mail para {}:\n{}", to, text);
        };
    }
}
