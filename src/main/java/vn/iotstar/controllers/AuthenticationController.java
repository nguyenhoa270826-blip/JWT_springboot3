package vn.iotstar.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.iotstar.entity.User;
import vn.iotstar.models.LoginResponse;
import vn.iotstar.models.LoginUserModel;
import vn.iotstar.models.RegisterUserModel;
import vn.iotstar.services.AuthenticationService;
import vn.iotstar.services.JwtService;

import java.util.Map;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<User> register(@RequestBody RegisterUserModel registerUser) {
        User registeredUser = authenticationService.signup(registerUser);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping(path = "/login")
    @Transactional
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserModel loginUser) {
        User authenticatedUser = authenticationService.authenticate(loginUser);

        String jwtToken = jwtService.generateToken(authenticatedUser);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(jwtToken);
        loginResponse.setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/login-rsa")
    @Transactional
    public ResponseEntity<LoginResponse> authenticateRsa(@RequestBody LoginUserModel loginUser) {
        User authenticatedUser = authenticationService.authenticate(loginUser);
        String rsaToken = jwtService.generateRsaToken(authenticatedUser, "ADMIN");

        LoginResponse loginResponse = new LoginResponse(rsaToken, jwtService.getExpirationTime());
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/jwe/encrypt")
    public ResponseEntity<Map<String, String>> encryptPayload(@RequestBody Map<String, Object> payload) {
        String subject = String.valueOf(payload.getOrDefault("sub", "user@iotstar.vn"));
        String jwe = jwtService.generateEncryptedJweToken(subject, payload);
        return ResponseEntity.ok(Map.of("jweToken", jwe));
    }

    @PostMapping("/jwe/decrypt")
    public ResponseEntity<Map<String, Object>> decryptPayload(@RequestBody Map<String, String> body) {
        Map<String, Object> claims = jwtService.decryptJweToken(body.get("jweToken"));
        return ResponseEntity.ok(claims);
    }
}