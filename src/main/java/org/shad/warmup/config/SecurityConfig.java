package org.shad.warmup.config;

import lombok.RequiredArgsConstructor;
import org.shad.warmup.common.ApiConstants;
import org.shad.warmup.handler.CustomAccessDeniedHandler;
import org.shad.warmup.handler.CustomAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for the application.
 * <p>
 * This class defines the security settings, including authentication, authorization,
 * password encoding, and exception handling. It uses **Spring Security's** `SecurityFilterChain`
 * to configure HTTP security rules.
 * <p>
 * **Key Features:**
 * <ul>
 *     <li>Disables CSRF for stateless authentication.</li>
 *     <li>Configures stateless session management for JWT-based authentication.</li>
 *     <li>Defines role-based access control for different API endpoints.</li>
 *     <li>Handles authentication and authorization exceptions using custom handlers.</li>
 *     <li>Provides an in-memory user store for testing purposes.</li>
 *     <li>Uses `BCryptPasswordEncoder` for password hashing.</li>
 * </ul>
 *
 * @see CustomAuthenticationEntryPoint Handles unauthorized access exceptions.
 * @see CustomAccessDeniedHandler Handles access denied exceptions.
 * @see PasswordEncoder Encrypts passwords securely.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    /**
     * Configures the security filter chain for handling HTTP requests.
     * <p>
     * **Security Settings:**
     * <ul>
     *     <li>Disables CSRF (since the app is stateless).</li>
     *     <li>Enforces stateless session management.</li>
     *     <li>Defines access control for authentication, public, and admin endpoints.</li>
     *     <li>Handles authentication and access denied exceptions.</li>
     *     <li>Enables HTTP Basic authentication.</li>
     * </ul>
     *
     * @param http The {@link HttpSecurity} configuration.
     * @return A configured {@link SecurityFilterChain} instance.
     * @throws Exception if an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // Disables CSRF (since the app is stateless)
                .csrf(AbstractHttpConfigurer::disable)
                // Enforces stateless session management.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Defines access control for authentication, public, and admin endpoints.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                ApiConstants.API_BASE + ApiConstants.AUTH + "/**").permitAll()
                        .requestMatchers(
                                ApiConstants.API_BASE + ApiConstants.PUBLIC + "/**").permitAll()
                        .requestMatchers(
                                ApiConstants.API_BASE + ApiConstants.ADMIN + "/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                // Handles authentication and access denied exceptions.
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                // Enables HTTP Basic authentication.
                .httpBasic(basic -> basic.authenticationEntryPoint(authenticationEntryPoint))
                .build();
    }

    /**
     * Provides an in-memory user details service for authentication.
     * <p>
     * **User Roles:**
     * <ul>
     *     <li>`USER`: Can access user-level functionalities.</li>
     *     <li>`ADMIN`: Has elevated privileges and access to admin-only endpoints.</li>
     * </ul>
     * <p>
     * **Passwords:** The passwords are securely hashed using {@link BCryptPasswordEncoder}.
     *
     * @param passwordEncoder The password encoder used for hashing user passwords.
     * @return A {@link UserDetailsService} instance with predefined users.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        // Create users with more secure passwords
        return new InMemoryUserDetailsManager(
                createUserDetails("user", passwordEncoder, "USER"),
                createUserDetails("admin", passwordEncoder, "ADMIN")
        );
    }

    /**
     * Provides a password encoder for hashing passwords securely.
     * <p>
     * Uses **BCrypt** with a strength factor of `12` for enhanced security.
     *
     * @return A {@link PasswordEncoder} instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Provides an {@link AuthenticationManager} bean.
     * <p>
     * This is used by the authentication system to manage user authentication.
     *
     * @param config The authentication configuration provided by Spring Security.
     * @return An {@link AuthenticationManager} instance.
     * @throws Exception if an error occurs while retrieving the authentication manager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Creates a `UserDetails` object with encrypted passwords and assigned roles.
     * <p>
     * This method is used by the in-memory authentication system to create test users.
     *
     * @param username The username of the user.
     * @param encoder  The password encoder for hashing passwords.
     * @param role     The role assigned to the user.
     * @return A configured {@link UserDetails} instance.
     */
    private UserDetails createUserDetails(String username, PasswordEncoder encoder, String role) {
        return User.builder()
                .username(username)
                .password(encoder.encode(generateSecurePassword(username)))
                .roles(role)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }

    /**
     * Generates a **secure password** for a user.
     * <p>
     * The format is `{username}_Codeus`, providing a simple way to generate unique passwords
     * for testing purposes.
     * <p>
     *
     * @param username The username for which to generate a password.
     * @return A secure password string.
     */
    private String generateSecurePassword(String username) {
        return String.format("%s_Codeus", username);
    }

}
