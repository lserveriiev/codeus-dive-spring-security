package org.shad.warmup.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shad.warmup.common.ApiResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom authentication entry point for handling **401 Unauthorized** responses.
 * <p>
 * This handler is triggered when a user attempts to access a secured resource
 * **without authentication**. Instead of returning a default HTML error page,
 * it returns a standardized **JSON error response**.
 * <p>
 * **Key Features:**
 * <ul>
 *     <li>Logs unauthorized access attempts.</li>
 *     <li>Returns an HTTP status of **401 Unauthorized**.</li>
 *     <li>Sends a structured JSON response using {@link ApiResponse}.</li>
 * </ul>
 * <p>
 * **Example JSON response:**
 * {
 *     "status": "error",
 *     "message": "Unauthorized: Authentication is required",
 *     "data": null,
 *     "timestamp": "2024-02-24T14:30:00.123"
 * }
 *
 * @see AuthenticationEntryPoint Default Spring Security interface for handling authentication failures.
 * @see org.shad.warmup.common.ApiResponse API response wrapper used for error responses.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper;

    /**
     * Handles unauthorized access attempts by returning a **401 Unauthorized** JSON response.
     * <p>
     * This method is invoked when an unauthenticated user tries to access a secured resource.
     * It:
     * <ul>
     *     <li>Logs the unauthorized attempt.</li>
     *     <li>Sets the response status to **401 Unauthorized**.</li>
     *     <li>Writes an error message as a JSON response.</li>
     * </ul>
     *
     * @param request        The HTTP request that resulted in an authentication failure.
     * @param response       The HTTP response sent back to the client.
     * @param authException  The exception representing the authentication failure.
     * @throws IOException If an error occurs while writing the response.
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        log.warn("Unauthorized access: {}", authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiResponse<?> apiResponse =
                ApiResponse.error("Unauthorized: " + authException.getMessage());
        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
