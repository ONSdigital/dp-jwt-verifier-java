package com.github.onsdigital.exceptions;

public class JWTTokenExpiredException extends RuntimeException {

    /**
     * Construct a new {@link JWTTokenExpiredException}.
     *
     * @param message the exception message
     */
    public JWTTokenExpiredException(String message) {
        this(message, null);
    }

    /**
     * Construct a new {@link JWTTokenExpiredException} wrapping an exception containing the original cause.
     *
     * @param message the exception message
     * @param cause   the {@link Throwable} that originally caused the issue
     */
    public JWTTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
