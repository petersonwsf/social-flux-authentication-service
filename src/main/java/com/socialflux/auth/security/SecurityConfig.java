package com.socialflux.auth.security;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.service.RevocationRegistry;
import com.socialflux.auth.web.ApiError;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.nio.charset.StandardCharsets;
import java.time.Clock;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String[] PUBLIC = {
            "/auth/register", "/auth/login", "/auth/refresh", "/auth/logout",
            "/auth/verify-email", "/auth/forgot-password", "/auth/reset-password",
            "/.well-known/jwks.json"
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder decoder, RevocationRegistry revocations,
                                            AuthProperties properties, Clock clock) throws Exception {
        http
                .csrf(csrf -> csrf.disable())          // substituído por SameSite + OriginCheckFilter (sem sessão no servidor)
                .cors(cors -> cors.disable())          // mesma origem via Caddy
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC).permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(unauthorized())
                        .accessDeniedHandler(forbidden()))
                .headers(headers -> headers
                        .cacheControl(Customizer.withDefaults())
                        .contentTypeOptions(Customizer.withDefaults())
                        .frameOptions(frame -> frame.deny()))
                .addFilterBefore(new OriginCheckFilter(properties), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new BearerAuthenticationFilter(decoder, revocations, properties, clock),
                        UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private static AuthenticationEntryPoint unauthorized() {
        return (request, response, exception) -> write(response, HttpServletResponse.SC_UNAUTHORIZED,
                ApiError.of("unauthorized", "Não autenticado"));
    }

    private static AccessDeniedHandler forbidden() {
        return (request, response, exception) -> write(response, HttpServletResponse.SC_FORBIDDEN,
                ApiError.of("forbidden", "Acesso negado"));
    }

    private static void write(HttpServletResponse response, int status, ApiError error) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(error.toJson());
    }
}
