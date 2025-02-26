package org.shad.taskJWT.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shad.taskJWT.service.JwtService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT-based authentication filter that processes bearer tokens in request headers.
 * <p>
 * This filter intercepts incoming HTTP requests, extracts and validates JWT tokens
 * from the Authorization header, and establishes the security context for authenticated
 * users. It's a critical component in the stateless authentication flow, enabling
 * authenticated access to protected resources without session management.
 * <p>
 * The filter is designed to:
 * <ul>
 *   <li>Skip authentication for specific endpoints (like login/auth endpoints)</li>
 *   <li>Extract JWT tokens from the Authorization header</li>
 *   <li>Validate tokens and extract user information</li>
 *   <li>Establish the SecurityContext with appropriate user details and authorities</li>
 *   <li>Handle various token-related exceptions gracefully</li>
 * </ul>
 * <p>
 * This implementation extends {@link OncePerRequestFilter} to ensure the filter
 * is only applied once per request, regardless of request dispatching.
 *
 * @see JwtService for JWT token processing
 * @see UserDetailsService for user information retrieval
 * @see SecurityContextHolder for security context management
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * Determines whether this filter should be skipped for the current request.
     * <p>
     * Authentication endpoints (paths starting with "/api/v1/auth/") are exempted
     * from JWT authentication to allow initial login and token acquisition without
     * requiring authentication. This prevents circular dependencies in the authentication
     * flow - users need to be able to authenticate without already having a token.
     * <p>
     * This method is called by the filter framework before {@link #doFilterInternal}
     * to determine if filtering should be applied.
     *
     * @param request the current HTTP request
     * @return true if the filter should not be applied to this request, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/v1/auth/");
    }

    /**
     * Core filter method that processes JWT authentication for each applicable request.
     * <p>
     * This method:
     * <ol>
     *   <li>Extracts the JWT token from the Authorization header (if present)</li>
     *   <li>Validates the token and extracts the username</li>
     *   <li>Loads the user details from the UserDetailsService</li>
     *   <li>Verifies the token is valid for this user</li>
     *   <li>Creates an authentication token with the user's authorities</li>
     *   <li>Establishes the SecurityContext with this authentication</li>
     * </ol>
     * <p>
     * If any step fails (missing token, invalid token, etc.), the filter will
     * not establish authentication, effectively denying access to protected resources.
     * The filter handles various JWT-related exceptions and logs appropriate messages,
     * but allows the request to continue down the filter chain, where other
     * security mechanisms will handle the unauthenticated request.
     *
     * @param request the HTTP request being processed
     * @param response the HTTP response being created
     * @param filterChain the filter chain for executing the next filter
     * @throws ServletException if a servlet error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer")) {
            try {
                String token = authHeader.substring(7);
                String username = jwtService.extractUsername(token);

                if (username != null
                        && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (jwtService.isTokenValid(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);

                        // Add helpful debug logging
                        log.debug("User '{}' successfully authenticated via JWT", username);
                    } else {
                        log.warn("Invalid JWT token for user: {}", username);
                    }
                }
            } catch (ExpiredJwtException e) {
                log.warn("JWT token has expired: {}", e.getMessage());
            } catch (MalformedJwtException e) {
                log.warn("Malformed JWT token: {}", e.getMessage());
            } catch (SignatureException e) {
                log.warn("Invalid JWT signature: {}", e.getMessage());
            } catch (Exception e) {
                log.error("JWT Authentication error: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
