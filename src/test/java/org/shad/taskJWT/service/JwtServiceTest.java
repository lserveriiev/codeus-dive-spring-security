package org.shad.taskJWT.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.shad.taskJWT.config.JwtProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtProperties jwtProperties;

    private JwtService jwtService;
    private UserDetails userDetails;
    private List<GrantedAuthority> authorities;


    private static final String TEST_SECRET =
            "9FE731B56C152D78B780CE60C2E28AF73FD8BE454E98F87A5B6CE72C9DD84F9C42B8C9D1F0123456789ABCDEF0123456789ABCDEF";
    private static final String TEST_ISSUER = "test-issuer";
    private static final Duration TEST_EXPIRATION = Duration.parse("PT1H");

    @BeforeEach
    void setUp() {
        lenient().when(jwtProperties.getSecret()).thenReturn(TEST_SECRET);
        lenient().when(jwtProperties.getExpiration()).thenReturn(TEST_EXPIRATION);
        lenient().when(jwtProperties.getIssuer()).thenReturn(TEST_ISSUER);

        // Create JWT service with mocked properties
        jwtService = new JwtService(jwtProperties);

        // Create test authorities and user
        authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"));

        userDetails = new User("testuser", "password", authorities);
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should generate valid token with user details")
        void shouldGenerateValidToken() {
            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            assertNotNull(token);
            assertFalse(token.isEmpty());

            // Verify token can be parsed back
            String username = jwtService.extractUsername(token);
            assertEquals("testuser", username);
        }

        @Test
        @DisplayName("Should include correct user authorities in token")
        void shouldIncludeUserAuthorities() {
            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            Object extractedAuthorities = jwtService.extractAuthorities(token);
            assertNotNull(extractedAuthorities, "Authorities should be included in token");

            // Note: The exact format depends on how authorities are serialized by JWT
            // Typically, we need to convert and then compare
            assertThat(extractedAuthorities.toString()).contains("ROLE_USER");
            assertThat(extractedAuthorities.toString()).contains("ROLE_ADMIN");
        }

        @Test
        @DisplayName("Should include correct issuer in token")
        void shouldIncludeCorrectIssuer() {
            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            Claims claims = jwtService.extractAllClaims(token);
            assertEquals(TEST_ISSUER, claims.getIssuer());
        }

        @Test
        @DisplayName("Should create token with proper expiration")
        void shouldCreateTokenWithProperExpiration() {
            // Given
            long currentTimeMillis = System.currentTimeMillis();

            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            Date expiration = jwtService.extractClaim(token, Claims::getExpiration);

            // Verify expiration is roughly TEST_EXPIRATION milliseconds in the future
            // Allow 10 second margin for test execution
            long expectedExpirationTime = currentTimeMillis + TEST_EXPIRATION.toMillis();
            long actualExpirationTime = expiration.getTime();

            // The expiration time should be within 10 seconds of expected
            assertTrue(Math.abs(expectedExpirationTime - actualExpirationTime) < 10000,
                    "Expiration time should be approximately " + TEST_EXPIRATION + "ms in the future");
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should validate token for the correct user")
        void shouldValidateTokenForCorrectUser() {
            // Given
            String token = jwtService.generateToken(userDetails);

            // When
            boolean isValid = jwtService.isTokenValid(token, userDetails);

            // Then
            assertTrue(isValid, "Token should be valid for the user it was generated for");
        }

        @Test
        @DisplayName("Should reject token for different user")
        void shouldRejectTokenForDifferentUser() {
            // Given
            String token = jwtService.generateToken(userDetails);
            UserDetails differentUser = new User("otheruser", "password", authorities);

            // When
            boolean isValid = jwtService.isTokenValid(token, differentUser);

            // Then
            assertFalse(isValid, "Token should not be valid for a different user");
        }

        @Test
        @DisplayName("Should reject expired token")
        void shouldRejectExpiredToken() throws Exception {
            // Given
            // Override the expiration to a very short time
            when(jwtProperties.getExpiration()).thenReturn(Duration.ofMillis(1L));

            // Generate token with 1ms expiration
            String token = jwtService.generateToken(userDetails);

            // Wait for token to expire
            Thread.sleep(10);

            // When & Then
            assertFalse(jwtService.isTokenValid(token, userDetails),
                    "Expired token should not be valid");
        }

        @Test
        @DisplayName("Should reject token with wrong signature")
        void shouldRejectTokenWithWrongSignature() {
            // Given
            String token = jwtService.generateToken(userDetails);

            // Modify the last character of the token (in the signature part)
            String tamperedToken = tamperWithSignature(token);

            // When & Then
            assertThatThrownBy(() -> jwtService.extractUsername(tamperedToken))
                    .isInstanceOf(SignatureException.class);

            assertFalse(jwtService.isTokenValid(tamperedToken, userDetails),
                    "Token with incorrect signature should not be valid");
        }

        @Test
        @DisplayName("Should reject malformed token")
        void shouldRejectMalformedToken() {
            // Given
            String malformedToken = "not.a.valid.jwt.token";

            // When & Then
            assertFalse(jwtService.isTokenValid(malformedToken, userDetails),
                    "Malformed token should not be valid");
        }

        private String tamperWithSignature(String token) {
            // A simple way to tamper with the signature: replace the last character
            if (!token.isEmpty()) {
                char lastChar = token.charAt(token.length() - 1);
                char replacementChar = (lastChar == 'A') ? 'B' : 'A';
                return token.substring(0, token.length() - 1) + replacementChar;
            }
            return token;
        }
    }

    @Nested
    @DisplayName("Claims Extraction Tests")
    class ClaimsExtractionTests {

        @Test
        @DisplayName("Should extract username from token")
        void shouldExtractUsername() {
            // Given
            String token = jwtService.generateToken(userDetails);

            // When
            String username = jwtService.extractUsername(token);

            // Then
            assertEquals(userDetails.getUsername(), username);
        }

        @Test
        @DisplayName("Should extract issuedAt date from token")
        void shouldExtractIssuedAtDate() {
            // Given
            long beforeTokenGeneration = System.currentTimeMillis();
            String token = jwtService.generateToken(userDetails);
            long afterTokenGeneration = System.currentTimeMillis();

            // When
            Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);

            // Then
            assertNotNull(issuedAt);
            assertTrue(issuedAt.getTime() >= beforeTokenGeneration - 1000);
            assertTrue(issuedAt.getTime() <= afterTokenGeneration + 1000);
        }

        @Test
        @DisplayName("Should extract all claims from token")
        void shouldExtractAllClaims() {
            // Given
            String token = jwtService.generateToken(userDetails);

            // When
            Claims claims = jwtService.extractAllClaims(token);

            // Then
            assertNotNull(claims);
            assertEquals(userDetails.getUsername(), claims.getSubject());
            assertEquals(TEST_ISSUER, claims.getIssuer());
            assertNotNull(claims.getIssuedAt());
            assertNotNull(claims.getExpiration());
            assertNotNull(claims.get("roles"));
        }

    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle ExpiredJwtException")
        void shouldHandleExpiredJwtException() throws Exception {
            // Given - Create a token that's already expired
            Date now = new Date();
            Date past = new Date(now.getTime() - 1000); // 1 second in the past

            String expiredToken = io.jsonwebtoken.Jwts.builder()
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(past)
                    .setExpiration(past) // Expired token
                    .setIssuer(TEST_ISSUER)
                    .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(TEST_SECRET.getBytes()))
                    .compact();

            // When & Then
            assertThatThrownBy(() -> jwtService.extractAllClaims(expiredToken))
                    .isInstanceOf(ExpiredJwtException.class);

            // Validation should return false rather than throwing
            assertFalse(jwtService.isTokenValid(expiredToken, userDetails));
        }

        @Test
        @DisplayName("Should handle SignatureException")
        void shouldHandleSignatureException() {

            String token = jwtService.generateToken(userDetails);
            String[] parts = token.split("\\.");

            String tamperedSignature = new StringBuilder(parts[2]).reverse().toString();
            String tamperedToken = parts[0] + "." + parts[1] + "." + tamperedSignature;

            assertThatThrownBy(() -> {
                Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))  // Need access to the same key
                        .build()
                        .parseClaimsJws(tamperedToken);
            }).isInstanceOf(SignatureException.class);

            assertFalse(jwtService.isTokenValid(tamperedToken, userDetails));
        }
        @Test
        @DisplayName("Should handle malformed JWT token")
        void shouldHandleMalformedJwtException() {

            String malformedToken = "not.a.valid.jwt.token";
            assertThatThrownBy(() -> jwtService.extractAllClaims(malformedToken))
                    .isInstanceOf(JwtException.class);

            boolean result = jwtService.isTokenValid(malformedToken, userDetails);
            assertFalse(result, "Validation should return false for malformed tokens");
        }

        private String tamperWithSignature(String token) {
            String[] parts = token.split("\\.");
            if (parts.length == 3) {
                // Modify the signature part (last part)
                return parts[0] + "." + parts[1] + "." + parts[2].replace('a', 'b');
            }
            return token;
        }
    }

    @Nested
    @DisplayName("Key Handling Tests")
    class KeyHandlingTests {

        @Test
        @DisplayName("Should work with Base64 encoded secret")
        void shouldWorkWithBase64EncodedSecret() {
            // Given
            String base64Secret = Base64.getEncoder().encodeToString(TEST_SECRET.getBytes());
            when(jwtProperties.getSecret()).thenReturn(base64Secret);

            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            assertNotNull(token);
            assertTrue(jwtService.isTokenValid(token, userDetails));
        }

        @Test
        @DisplayName("Should work with different character encodings")
        void shouldWorkWithDifferentCharacterEncodings() {
            // Given - a secret with sufficient length, even with non-ASCII characters
            // Hebrew characters, expanded to ensure sufficient key length
            String nonAsciiSecret = "מפתח־סודי־מאוד־מפתח־סודי־מאוד־מפתח־סודי־מאוד־מפתח־סודי־מאוד";
            when(jwtProperties.getSecret()).thenReturn(nonAsciiSecret);

            // When
            String token = jwtService.generateToken(userDetails);

            // Then
            assertNotNull(token);
            assertTrue(jwtService.isTokenValid(token, userDetails));
        }
    }
}
