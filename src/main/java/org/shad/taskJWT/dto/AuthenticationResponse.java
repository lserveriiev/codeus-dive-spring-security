package org.shad.taskJWT.dto;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.shad.taskJWT.config.JwtProperties;

import java.time.LocalDateTime;

/**
 * Response DTO containing JWT authentication information.
 * This class provides all necessary details about the issued token
 * to help clients manage their authentication state.
 * <p>
 * Implemented as a record for immutability and conciseness.
 */
public record AuthenticationResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("issued_at")
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS")
        LocalDateTime issuedAt,

        @JsonProperty("expires_at")
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS")
        LocalDateTime expiresAt,

        String issuer,
        String username
) {
    /**
     * Static factory method to create a response from a token and properties.
     * Calculates expiration based on the properties configuration.
     */
    public static AuthenticationResponse fromToken(
            String token,
            String username,
            JwtProperties jwtProperties) {

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiration = now.plusSeconds(jwtProperties.getExpiration().getSeconds());

        return new AuthenticationResponse(
                token,
                "Bearer",
                now,
                expiration,
                jwtProperties.getIssuer(),
                username
        );
    }
}
