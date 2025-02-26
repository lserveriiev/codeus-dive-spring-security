package org.shad.taskJWT.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shad.taskJWT.config.JwtProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service responsible for JWT (JSON Web Token) operations in the application.
 * <p>
 * This service handles all JWT-related functionality including:
 * <ul>
 *   <li>Token generation for authenticated users</li>
 *   <li>Token validation and verification</li>
 *   <li>Extracting claims and user information from tokens</li>
 *   <li>Managing token expiration</li>
 * </ul>
 * <p>
 * JWT tokens are used to maintain stateless authentication in the application.
 * Each token contains encrypted information about the user and their permissions,
 * allowing the server to authenticate requests without maintaining session state.
 * <p>
 * This implementation for JWT handling including:
 * <ul>
 *   <li>Secure key management</li>
 *   <li>Proper exception handling</li>
 *   <li>Comprehensive claim validation</li>
 *   <li>User-specific token validation</li>
 * </ul>
 *
 * @see JwtProperties for configuration options
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;

    /**
     * Generates a JWT token for the given user.
     * <p>
     * This method creates a signed JWT token containing:
     * <ul>
     *   <li>User identity (username as the subject)</li>
     *   <li>User authorities/roles for authorization</li>
     *   <li>Token issuance time</li>
     *   <li>Token expiration time (based on configured expiration period)</li>
     *   <li>Token issuer</li>
     * </ul>
     * <p>
     * The token is signed using HMAC-SHA256 (HS256) with the application's secret key,
     * ensuring it cannot be modified without detection.
     *
     * @param userDetails the authenticated user for whom to generate the token
     * @return a compact, URL-safe JWT string
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities());

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getExpiration().toMillis());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .setIssuer(jwtProperties.getIssuer())
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates a JWT token for a specific user.
     * <p>
     * This method performs multiple validation checks:
     * <ul>
     *   <li>Verifies the token's cryptographic signature</li>
     *   <li>Checks that the token's subject (username) matches the provided user</li>
     *   <li>Ensures the token has not expired</li>
     * </ul>
     * <p>
     * Any exception during validation (such as signature failures, expired tokens, etc.)
     * is caught and logged, resulting in a failed validation rather than exceptions
     * propagating to the caller.
     *
     * @param token       the JWT token string to validate
     * @param userDetails the user against which to validate the token
     * @return true if the token is valid for the specified user, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired: {}", token);
            return false;
        } catch (JwtException e) {
            log.error("Invalid JWT token: {}", token);
            return false;
        }
    }

    /**
     * Extracts the username from a JWT token.
     * <p>
     * This is a convenience method that extracts the Subject claim from the token,
     * which represents the username in our token design.
     * <p>
     * This method will throw exceptions if the token is invalid (malformed, expired,
     * or has an invalid signature). Callers should handle these exceptions or use
     * {@link #isTokenValid(String, UserDetails)} which handles exceptions internally.
     *
     * @param token the JWT token string
     * @return the username extracted from the token's subject claim
     * @throws JwtException if the token cannot be parsed or is invalid
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts all JWT claims from a token string.
     * <p>
     * This method parses the JWT token, validates its signature, and returns the complete
     * set of claims contained in the token body. It performs full verification of the token,
     * including signature validation against the application's secret key.
     * <p>
     * The method catches and rethrows various JWT exceptions with appropriate logging,
     * making the specific failure reason visible in logs while preserving the exception
     * type for proper handling by callers.
     *
     * @param token the JWT token string to parse
     * @return the Claims object containing all token claims
     * @throws ExpiredJwtException   if the token has expired
     * @throws SignatureException    if the token has an invalid signature
     * @throws MalformedJwtException if the token is malformed
     * @throws JwtException          for any other JWT parsing/validation error
     */
    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.error("Malformed JWT token: {}", e.getMessage());
            throw e;
        } catch (JwtException e) {
            log.error("JWT token validation error: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Extracts a specific claim from a JWT token using a resolver function.
     * <p>
     * This generic method allows extracting any claim from the token by providing
     * a function that selects the desired claim from the Claims object. It provides
     * a flexible way to access both standard and custom claims.
     * <p>
     * For example, to extract the expiration date:
     * <pre>
     * Date expiration = extractClaim(token, Claims::getExpiration);
     * </pre>
     * <p>
     * This method relies on {@link #extractAllClaims(String)} for token parsing and
     * validation, so it will propagate any exceptions thrown during that process.
     *
     * @param <T>            the type of the claim to extract
     * @param token          the JWT token string
     * @param claimsResolver function that extracts the desired claim from the Claims object
     * @return the extracted claim value
     * @throws JwtException if the token is invalid or cannot be parsed
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Creates a cryptographic key for JWT signing and verification.
     * <p>
     * This method handles creating the appropriate HMAC-SHA key from the configured secret.
     * It attempts to decode the secret as Base64 first (a common format for storing keys),
     * and falls back to using the raw bytes with UTF-8 encoding if Base64 decoding fails.
     * <p>
     * This approach provides flexibility in how the secret is stored in configuration
     * while ensuring the key is properly formatted for the JWT library.
     *
     * @return a Key suitable for JWT signing and verification
     */
    private Key getSigningKey() {
        try {
            // Try to decode Base64 encoded secret first
            byte[] keyBytes = Base64.getDecoder().decode(jwtProperties.getSecret());
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            // If not Base64 encoded, use raw bytes with proper UTF-8 encoding
            return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Checks if a JWT token has expired.
     * <p>
     * This method extracts the expiration date from the token and compares it to
     * the current time to determine if the token has expired.
     * <p>
     * It uses {@link #extractClaim(String, Function)} to get the expiration claim,
     * so any exceptions from token parsing will propagate to the caller.
     *
     * @param token the JWT token to check
     * @return true if the token has expired, false otherwise
     * @throws JwtException if the token is invalid or cannot be parsed
     */
    private boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }

    /**
     * Extracts user authorities/roles from a JWT token.
     * <p>
     * This method retrieves the "roles" claim from the token, which contains
     * the user's granted authorities. This is particularly useful in the authentication
     * filter for setting up the user's security context with the appropriate permissions.
     * <p>
     * The returned object structure will match how the authorities were serialized
     * during token generation, typically as a collection of authority objects.
     *
     * @param token the JWT token string
     * @return the authorities/roles data from the token
     * @throws JwtException if the token is invalid or cannot be parsed
     */
    public Object extractAuthorities(String token) {
        return extractAllClaims(token).get("roles");
    }

}
