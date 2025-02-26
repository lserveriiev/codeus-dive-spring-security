package org.shad.taskJWT.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object (DTO) representing an authentication request.
 * <p>
 * This record is used to capture user credentials during the authentication process.
 * It enforces basic validation to ensure that both username and password fields are not blank.
 * <p>
 * {@code @NotBlank} annotations ensure the fields are non-null and contain at least one non-whitespace character.
 * <p>
 * Example usage:
 * <pre>
 * AuthenticationRequest request = new AuthenticationRequest("user123", "securePassword");
 * </pre>
 *
 * @param username the username of the user attempting to authenticate (must not be blank)
 * @param password the password of the user attempting to authenticate (must not be blank)
 */
public record AuthenticationRequest(
    @NotBlank(message = "Username is required")
    String username,

    @NotBlank(message = "Password is required")
    String password
)
{
}
