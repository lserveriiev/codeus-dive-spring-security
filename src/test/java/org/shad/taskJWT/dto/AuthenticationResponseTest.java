package org.shad.taskJWT.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.shad.taskJWT.config.JwtProperties;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticationResponseTest {
    private JwtProperties jwtProperties;
    private static final String TEST_TOKEN = "test.jwt.token";
    private static final String TEST_USERNAME = "testUser";
    private static final String TEST_ISSUER = "testIssuer";
    private static final Duration EXPIRATION = Duration.parse("PT1H"); // 1 hour

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule()); // Fix for LocalDateTime serialization

        jwtProperties = new JwtProperties();
        jwtProperties.setSecret("testSecret");
        jwtProperties.setExpiration(EXPIRATION);
        jwtProperties.setIssuer(TEST_ISSUER);
    }

    @Test
    @DisplayName("Should create AuthenticationResponse with correct expiration time")
    void shouldCreateAuthenticationResponseWithCorrectExpiration() {
        // Given
        LocalDateTime beforeCall = LocalDateTime.now();

        // When
        AuthenticationResponse response = AuthenticationResponse.fromToken(TEST_TOKEN, TEST_USERNAME, jwtProperties);

        // Then
        assertNotNull(response);
        assertEquals(TEST_TOKEN, response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(TEST_ISSUER, response.issuer());
        assertEquals(TEST_USERNAME, response.username());

        // Check issuedAt is within a reasonable range
        assertTrue(response.issuedAt().isAfter(beforeCall) || response.issuedAt().isEqual(beforeCall));

        // Check expiresAt is correctly calculated
        LocalDateTime expectedExpiration = response.issuedAt().plusNanos(EXPIRATION.toMillis() * 1000000);
        assertEquals(expectedExpiration, response.expiresAt());
    }

    @Test
    @DisplayName("Should correctly serialize AuthenticationResponse to JSON")
    void shouldSerializeToJson() throws Exception {
        // Given
        AuthenticationResponse response = AuthenticationResponse.fromToken(TEST_TOKEN, TEST_USERNAME, jwtProperties);

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule()); // ✅ Fix for LocalDateTime

        // When
        String json = objectMapper.writeValueAsString(response);

        // Then
        assertTrue(json.contains("\"access_token\":\"" + TEST_TOKEN + "\""));
        assertTrue(json.contains("\"token_type\":\"Bearer\""));
        assertTrue(json.contains("\"issuer\":\"" + TEST_ISSUER + "\""));
        assertTrue(json.contains("\"username\":\"" + TEST_USERNAME + "\""));
        assertTrue(json.contains("\"issued_at\""));
        assertTrue(json.contains("\"expires_at\""));
    }
}
