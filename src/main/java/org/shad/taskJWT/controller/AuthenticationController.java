package org.shad.taskJWT.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.shad.taskJWT.config.JwtProperties;
import org.shad.taskJWT.dto.AuthenticationRequest;
import org.shad.taskJWT.dto.AuthenticationResponse;
import org.shad.taskJWT.service.JwtService;
import org.shad.warmup.common.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST Controller responsible for user authentication and JWT token generation.
 * <p>
 * This controller handles login requests by validating user credentials,
 * generating a JWT token upon successful authentication, and returning
 * the authentication response containing the token details.
 * <p>
 * The authentication process involves:
 * <ul>
 *     <li>Validating the username and password using {@link AuthenticationManager}</li>
 *     <li>Retrieving user details from {@link UserDetailsService}</li>
 *     <li>Generating a JWT token using {@link JwtService}</li>
 *     <li>Returning an {@link AuthenticationResponse} wrapped in {@link ApiResponse}</li>
 * </ul>
 *
 * <p>
 * **Endpoint Details:**
 * <ul>
 *     <li>POST /api/v1/auth/login → Authenticate a user and return a JWT token.</li>
 * </ul>
 *
 * @see JwtService for JWT token processing
 * @see UserDetailsService for loading user details
 * @see AuthenticationManager for authentication handling
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    /**
     * Authenticates a user and generates a JWT token.
     * <p>
     * This endpoint allows users to log in by providing their credentials.
     * If authentication is successful, a JWT token is generated and returned.
     * <p>
     * **Request Body:**
     * <pre>
     * {
     *     "username": "user123",
     *     "password": "securePassword"
     * }
     * </pre>
     * **Response Example:**
     * <pre>
     * {
     *     "status": "success",
     *     "data": {
     *         "access_token": "eyJhbGciOiJIUzI1NiIsInR...",
     *         "token_type": "Bearer",
     *         "issued_at": "2024-02-24T14:30:00.123",
     *         "expires_at": "2024-02-24T15:30:00.123",
     *         "issuer": "my-app",
     *         "username": "user123"
     *     }
     * }
     * </pre>
     *
     * @param request The authentication request containing username and password.
     * @return ResponseEntity containing the JWT authentication response.
     * @throws org.springframework.security.authentication.BadCredentialsException If authentication fails.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> login(
            @Valid @RequestBody AuthenticationRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.username());
        String token = jwtService.generateToken(userDetails);
        AuthenticationResponse tokenResponse = AuthenticationResponse
                .fromToken(
                        token,
                        request.username(),
                        jwtProperties
                );

        return ResponseEntity.ok(ApiResponse.success(tokenResponse));
    }
}
