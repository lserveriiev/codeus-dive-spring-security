package org.shad.taskJWT.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Configuration properties for JWT (JSON Web Token) authentication.
 * <p>
 * This class is used to bind JWT-related properties from the application configuration file (e.g., `application.yml` or `application.properties`).
 * It allows easy customization of JWT settings without modifying the source code.
 * <p>
 * Expected properties in `application.yml`:
 * <pre>
 * jwt:
 *   secret: "your-secret-key"
 *   expiration-ms: 3600000
 *   issuer: "your-app-name"
 * </pre>
 * <p>
 * **Properties:**
 * <ul>
 *   <li>{@code secret} - The secret key used to sign JWT tokens.</li>
 *   <li>{@code expirationMs} - The expiration time of JWT tokens in milliseconds.</li>
 *   <li>{@code issuer} - The issuer name included in the JWT payload.</li>
 * </ul>
 */
@Slf4j
@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private Duration expiration;
    private String issuer;
}
