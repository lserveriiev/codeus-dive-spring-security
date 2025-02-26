package org.shad.warmup.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shad.warmup.common.ApiResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom handler for handling **403 Forbidden** errors in Spring Security.
 * <p>
 * This handler is triggered when a user tries to access a resource **without sufficient permissions**.
 * It:
 * <ul>
 *     <li>Logs the access denial event.</li>
 *     <li>Returns a JSON response with HTTP status **403 Forbidden**.</li>
 *     <li>Includes an error message in the response body.</li>
 * </ul>
 * <p>
 * **Example JSON response:**
 * <pre>
 * {
 *     "status": "error",
 *     "message": "Access denied: You do not have permission to access this resource",
 *     "data": null,
 *     "timestamp": "2024-02-24T14:30:00.123"
 * }
 * </pre>
 *
 * @see AccessDeniedHandler Default Spring Security interface for handling access denial.
 * @see org.shad.warmup.common.ApiResponse API response wrapper used for error responses.
 */

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper;

    /**
     * Handles access denied exceptions and returns a standardized JSON response.
     * <p>
     * This method is invoked when a user attempts to access a secured resource without
     * the necessary permissions. It:
     * <ul>
     *     <li>Logs the access denial.</li>
     *     <li>Sets the HTTP response status to **403 Forbidden**.</li>
     *     <li>Writes an error message as a JSON response.</li>
     * </ul>
     *
     * @param request   The HTTP request that resulted in access denial.
     * @param response  The HTTP response to be sent back to the client.
     * @param exception The exception representing the access denial.
     * @throws IOException If an error occurs while writing the response.
     */
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException exception) throws IOException {

        log.warn("Access denied: {}", exception.getMessage());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiResponse<?> apiResponse = ApiResponse.error("Unauthorized: " + exception.getMessage());
        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
