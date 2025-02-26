package org.shad.warmup.common;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Defines constants for API versioning and endpoint paths.
 * <p>
 * This class provides a centralized location for defining API path constants,
 * ensuring consistency across the application.
 * <p>
 * The API follows versioning (`/api/v1`) and includes standard endpoint prefixes:
 * <ul>
 *     <li>{@link #API_BASE} - Base path for all API endpoints.</li>
 *     <li>{@link #PUBLIC} - Public endpoints accessible without authentication.</li>
 *     <li>{@link #ADMIN} - Admin-only endpoints requiring authentication and authorization.</li>
 *     <li>{@link #AUTH} - Authentication-related endpoints (e.g., login, token refresh).</li>
 * </ul>
 * <p>
 * Example usage:
 * <pre>
 * &#64;RequestMapping(ApiConstants.API_BASE + ApiConstants.PUBLIC)
 * public class PublicController { ... }
 * </pre>
 * <p>
 * This class is marked as {@code final} to prevent inheritance, and the constructor is private
 * to ensure it is never instantiated.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ApiConstants {

    public static final String API_BASE = "/api/v1";
    public static final String PUBLIC = "/public";
    public static final String ADMIN = "/admin";
    public static final String AUTH = "/auth";

}
