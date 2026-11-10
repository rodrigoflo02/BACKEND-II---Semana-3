package com.petsalud.backendpetsalud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptListener {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptListener.class);

    @EventListener
    public void registrarFallo(AbstractAuthenticationFailureEvent event) {
        log.warn("Intento de autenticación fallido, identificador={}",
                Integer.toHexString(event.getAuthentication().getName().hashCode()));
    }

    @EventListener
    public void registrarExito(AuthenticationSuccessEvent event) {
        log.info("Autenticación correcta, identificador={}",
                Integer.toHexString(event.getAuthentication().getName().hashCode()));
    }
}
