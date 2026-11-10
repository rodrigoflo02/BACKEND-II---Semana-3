package com.petsalud.backendpetsalud;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.petsalud.backendpetsalud.entity.Producto;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.ProductoRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import com.petsalud.backendpetsalud.security.UsuarioDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTests {

    private static final String PASSWORD = "ClaveSegura123!";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UsuarioRepository usuarioRepository;
    @Autowired
    private MascotaRepository mascotaRepository;
    @Autowired
    private ProductoRepository productoRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UsuarioDetailsService usuarioDetailsService;
    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void prepararUsuarios() {
        productoRepository.deleteAll();
        mascotaRepository.deleteAll();
        usuarioRepository.deleteAll();
        guardarUsuario("cliente@petsalud.cl", Rol.CLIENTE);
        guardarUsuario("otro@petsalud.cl", Rol.CLIENTE);
        guardarUsuario("gerente@petsalud.cl", Rol.GERENTE);
    }

    @Test
    void registroCifraLaClaveYNoPermiteAsignarPrivilegios() throws Exception {
        String request = """
                {"email":"nuevo@petsalud.cl","password":"ClaveNueva123!",
                 "nombre":"Ana","apellido":"Pérez","rol":"ADMIN"}
                """;

        String response = mockMvc.perform(post("/api/usuarios/registro")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString();

        JsonNode user = objectMapper.readTree(response);
        assertTrue(user.get("password") == null);
        assertTrue(user.get("rol").asText().equals("CLIENTE"));
        Usuario guardado = usuarioRepository.findByEmail("nuevo@petsalud.cl").orElseThrow();
        assertNotEquals("ClaveNueva123!", guardado.getPassword());
        assertTrue(passwordEncoder.matches("ClaveNueva123!", guardado.getPassword()));
    }

    @Test
    void loginEmiteJwtYRechazaTokensAlterados() throws Exception {
        String token = iniciarSesion("gerente@petsalud.cl");
        mockMvc.perform(get("/api/usuarios").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        String[] partes = token.split("\\.");
        partes[2] = (partes[2].charAt(0) == 'A' ? "B" : "A") + partes[2].substring(1);
        mockMvc.perform(get("/api/usuarios").header("Authorization", "Bearer " + String.join(".", partes)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rolesRestringenElListadoDeUsuarios() throws Exception {
        mockMvc.perform(get("/api/usuarios"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + iniciarSesion("cliente@petsalud.cl")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + iniciarSesion("gerente@petsalud.cl")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/productos/stock-bajo")
                        .param("cantidad", "5")
                        .header("Authorization", "Bearer " + iniciarSesion("cliente@petsalud.cl")))
                .andExpect(status().isForbidden());
    }

    @Test
    void clienteNoPuedeConsultarElPerfilDeOtroCliente() throws Exception {
        Long idPropio = usuarioRepository.findByEmail("cliente@petsalud.cl").orElseThrow().getId();
        Long idAjeno = usuarioRepository.findByEmail("otro@petsalud.cl").orElseThrow().getId();
        String token = iniciarSesion("cliente@petsalud.cl");

        mockMvc.perform(get("/api/usuarios/{id}", idPropio)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/usuarios/{id}", idAjeno)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void clienteSoloConsultaSusMascotasYCitas() throws Exception {
        Usuario propietario = usuarioRepository.findByEmail("cliente@petsalud.cl").orElseThrow();
        Long mascotaId = mascotaRepository.save(Mascota.builder()
                .nombre("Luna")
                .especie("Perro")
                .propietario(propietario)
                .build()).getId();
        String tokenPropietario = iniciarSesion("cliente@petsalud.cl");
        String tokenAjeno = iniciarSesion("otro@petsalud.cl");

        mockMvc.perform(get("/api/mascotas/{id}", mascotaId)
                        .header("Authorization", "Bearer " + tokenPropietario))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/mascotas/{id}", mascotaId)
                        .header("Authorization", "Bearer " + tokenAjeno))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/citas/mascota/{mascotaId}", mascotaId)
                        .header("Authorization", "Bearer " + tokenPropietario))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/citas/mascota/{mascotaId}", mascotaId)
                        .header("Authorization", "Bearer " + tokenAjeno))
                .andExpect(status().isForbidden());
    }

    @Test
    void bearerNoRequiereTokenCsrfYLaApiRespondeComoJsonAnteContenidoHtml() throws Exception {
        String maliciousMarkup = "<script>alert(1)</script>";
        String body = objectMapper.writeValueAsString(Producto.builder()
                .nombre(maliciousMarkup)
                .descripcion("Producto de prueba")
                .precio(BigDecimal.ONE)
                .stock(1)
                .categoria("prueba")
                .build());

        mockMvc.perform(post("/api/productos")
                        .header("Authorization", "Bearer " + iniciarSesion("gerente@petsalud.cl"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().string("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"));
    }

    @Test
    void consultaDeUsuarioNoInterpretaTextoDeInyeccionSql() {
        assertThrows(UsernameNotFoundException.class, () ->
                usuarioDetailsService.loadUserByUsername("gerente@petsalud.cl' OR '1'='1"));
        assertTrue(usuarioRepository.findByEmail("gerente@petsalud.cl").isPresent());
    }

    private void guardarUsuario(String email, Rol rol) {
        usuarioRepository.save(Usuario.builder()
                .email(email)
                .password(passwordEncoder.encode(PASSWORD))
                .nombre("Usuario")
                .apellido("Prueba")
                .rol(rol)
                .build());
    }

    private String iniciarSesion(String email) throws Exception {
        String body = objectMapper.writeValueAsString(
                java.util.Map.of("email", email, "password", PASSWORD));
        String response = mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).get("token").asText();
    }
}
