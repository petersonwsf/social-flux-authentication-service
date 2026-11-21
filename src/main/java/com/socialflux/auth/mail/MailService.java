package com.socialflux.auth.mail;

/** Envio de e-mails transacionais (verificação e redefinição de senha). */
public interface MailService {

    void send(String to, String subject, String text);
}
