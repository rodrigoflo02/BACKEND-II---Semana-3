package com.petsalud.backendpetsalud.dto;

public record TokenResponse(String token, String tipo, long expiraEnSegundos) {
}
