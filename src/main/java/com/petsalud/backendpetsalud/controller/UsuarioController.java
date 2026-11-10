package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.dto.RegistroRequest;
import com.petsalud.backendpetsalud.dto.UsuarioResponse;
import com.petsalud.backendpetsalud.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @PostMapping("/registro")
    public ResponseEntity<UsuarioResponse> registrarUsuario(@Valid @RequestBody RegistroRequest request) {
        Usuario usuario = Usuario.builder()
                .email(request.email())
                .password(request.password())
                .nombre(request.nombre())
                .apellido(request.apellido())
                .telefono(request.telefono())
                .direccion(request.direccion())
                .build();
        return ResponseEntity.ok(UsuarioResponse.desde(usuarioService.registrarUsuario(usuario)));
    }

    @GetMapping("/{id}")
    @PreAuthorize("@autorizacion.puedeVerUsuario(#id)")
    public ResponseEntity<UsuarioResponse> obtenerUsuarioPorId(@PathVariable Long id) {
        return usuarioService.obtenerUsuarioPorId(id)
                .map(UsuarioResponse::desde)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('GERENTE', 'ADMIN') or @autorizacion.esUsuarioActual(#id)")
    public ResponseEntity<UsuarioResponse> actualizarUsuario(@PathVariable Long id, @RequestBody Usuario usuario) {
        Usuario usuarioActualizado = usuarioService.actualizarUsuario(id, usuario);
        return ResponseEntity.ok(UsuarioResponse.desde(usuarioActualizado));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('GERENTE', 'ADMIN')")
    public ResponseEntity<Void> eliminarUsuario(@PathVariable Long id) {
        usuarioService.eliminarUsuario(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('GERENTE', 'ADMIN')")
    public ResponseEntity<List<UsuarioResponse>> listarUsuarios() {
        List<UsuarioResponse> usuarios = usuarioService.listarUsuarios().stream()
                .map(UsuarioResponse::desde)
                .toList();
        return ResponseEntity.ok(usuarios);
    }
}
