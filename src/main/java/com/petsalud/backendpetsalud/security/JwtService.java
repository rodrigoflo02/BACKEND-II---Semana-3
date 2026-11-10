package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Rol;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms}") long expirationMs) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secret);
            if (keyBytes.length < 32) {
                throw new IllegalStateException("JWT_SECRET debe contener al menos 256 bits");
            }
            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("JWT_SECRET debe ser una clave Base64 válida de al menos 256 bits", exception);
        }
        if (expirationMs <= 0) {
            throw new IllegalStateException("JWT_EXPIRATION_MS debe ser mayor que cero");
        }
        this.expirationMs = expirationMs;
    }

    public String generarToken(Authentication authentication) {
        Instant ahora = Instant.now();
        List<String> roles = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .toList();

        return Jwts.builder()
                .subject(authentication.getName())
                .claim("roles", roles)
                .issuedAt(Date.from(ahora))
                .expiration(Date.from(ahora.plusMillis(expirationMs)))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    public Authentication autenticarToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        List<?> roles = claims.get("roles", List.class);
        if (claims.getSubject() == null || claims.getSubject().isBlank()
                || roles == null || roles.isEmpty()
                || roles.stream().anyMatch(role -> !(role instanceof String))) {
            throw new JwtException("Token sin sujeto o roles válidos");
        }
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(String.class::cast)
                .map(Rol::valueOf)
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol.name()))
                .toList();

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
    }

    public long expiraEnSegundos() {
        return expirationMs / 1000;
    }
}
