package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Cita;
import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.entity.Notificacion;
import com.petsalud.backendpetsalud.entity.Recompensa;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.entity.Venta;
import com.petsalud.backendpetsalud.repository.CitaRepository;
import com.petsalud.backendpetsalud.repository.ExpedienteMedicoRepository;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import com.petsalud.backendpetsalud.repository.RecompensaRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import com.petsalud.backendpetsalud.repository.VentaRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("autorizacion")
public class AutorizacionService {

    private final UsuarioRepository usuarioRepository;
    private final MascotaRepository mascotaRepository;
    private final CitaRepository citaRepository;
    private final ExpedienteMedicoRepository expedienteRepository;
    private final NotificacionRepository notificacionRepository;
    private final RecompensaRepository recompensaRepository;
    private final VentaRepository ventaRepository;

    public AutorizacionService(
            UsuarioRepository usuarioRepository,
            MascotaRepository mascotaRepository,
            CitaRepository citaRepository,
            ExpedienteMedicoRepository expedienteRepository,
            NotificacionRepository notificacionRepository,
            RecompensaRepository recompensaRepository,
            VentaRepository ventaRepository) {
        this.usuarioRepository = usuarioRepository;
        this.mascotaRepository = mascotaRepository;
        this.citaRepository = citaRepository;
        this.expedienteRepository = expedienteRepository;
        this.notificacionRepository = notificacionRepository;
        this.recompensaRepository = recompensaRepository;
        this.ventaRepository = ventaRepository;
    }

    public boolean esUsuarioActual(Long usuarioId) {
        return usuarioId != null && usuarioRepository.findById(usuarioId)
                .map(usuario -> usuario.getEmail().equalsIgnoreCase(nombreActual()))
                .orElse(false);
    }

    public boolean puedeVerUsuario(Long usuarioId) {
        return esPersonal() || esUsuarioActual(usuarioId);
    }

    public boolean esPropietario(Long usuarioId) {
        return esUsuarioActual(usuarioId);
    }

    public boolean esPropietarioDeMascota(Long mascotaId) {
        return mascotaRepository.findById(mascotaId)
                .map(this::esPropietarioDe)
                .orElse(false);
    }

    public boolean puedeAgendarCita(Long mascotaId, Long veterinarioId) {
        if (tieneRol("VETERINARIO")) {
            return esVeterinarioActual(veterinarioId)
                    && mascotaRepository.existsById(mascotaId);
        }
        if (tieneRol("EMPLEADO", "GERENTE", "ADMIN")) {
            return true;
        }
        return tieneRol("CLIENTE") && esPropietarioDeMascota(mascotaId);
    }

    public boolean puedeVerMascota(Long mascotaId) {
        return mascotaRepository.findById(mascotaId)
                .map(mascota -> esPersonal() || esPropietarioDe(mascota))
                .orElse(false);
    }

    public boolean puedeVerCita(Long citaId) {
        return citaRepository.findById(citaId)
                .map(cita -> esPersonal() && (!tieneRol("VETERINARIO") || esVeterinarioAsignado(cita))
                        || esPropietarioDe(cita.getMascota()))
                .orElse(false);
    }

    public boolean puedeGestionarCita(Long citaId) {
        return citaRepository.findById(citaId)
                .map(cita -> tieneRol("ADMIN", "GERENTE", "EMPLEADO")
                        || tieneRol("VETERINARIO") && esVeterinarioAsignado(cita))
                .orElse(false);
    }

    public boolean esVeterinarioActual(Long usuarioId) {
        return usuarioId != null && tieneRol("VETERINARIO") && usuarioRepository.findById(usuarioId)
                .map(usuario -> usuario.getEmail().equalsIgnoreCase(nombreActual()))
                .orElse(false);
    }

    public boolean puedeVerExpediente(Long expedienteId) {
        return expedienteRepository.findById(expedienteId)
                .map(registro -> tieneRol("ADMIN", "VETERINARIO")
                        || esPropietarioDe(registro.getMascota()))
                .orElse(false);
    }

    public boolean puedeVerHistorialMascota(Long mascotaId) {
        return mascotaRepository.findById(mascotaId)
                .map(mascota -> tieneRol("ADMIN", "VETERINARIO") || esPropietarioDe(mascota))
                .orElse(false);
    }

    public boolean puedeVerNotificacion(Long notificacionId) {
        return notificacionRepository.findById(notificacionId)
                .map(notificacion -> esPersonal() || esPropietarioDe(notificacion.getUsuario()))
                .orElse(false);
    }

    public boolean puedeVerRecompensa(Long recompensaId) {
        return recompensaRepository.findById(recompensaId)
                .map(recompensa -> esPersonal() || esPropietarioDe(recompensa.getUsuario()))
                .orElse(false);
    }

    public boolean puedeVerVenta(Long ventaId) {
        return ventaRepository.findById(ventaId)
                .map(venta -> esPersonal() || esPropietarioDe(venta.getUsuario()))
                .orElse(false);
    }

    private boolean esPropietarioDe(Mascota mascota) {
        return mascota != null && mascota.getPropietario() != null
                && mascota.getPropietario().getEmail().equalsIgnoreCase(nombreActual());
    }

    private boolean esPropietarioDe(Usuario usuario) {
        return usuario != null && usuario.getEmail().equalsIgnoreCase(nombreActual());
    }

    private boolean esVeterinarioAsignado(Cita cita) {
        return cita.getVeterinario() != null
                && cita.getVeterinario().getEmail().equalsIgnoreCase(nombreActual());
    }

    private boolean esPersonal() {
        return tieneRol("VETERINARIO", "EMPLEADO", "GERENTE", "ADMIN");
    }

    private boolean tieneRol(String... roles) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> java.util.Arrays.stream(roles)
                        .anyMatch(role -> authority.getAuthority().equals("ROLE_" + role)));
    }

    private String nombreActual() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication == null ? "" : authentication.getName();
    }
}
