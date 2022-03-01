package com.github.onsdigital.exceptions;

/**
 * JWTVerificationException is the exception used for cases when verification of the JWT signature fails.
 */
public class JWTVerificationException extends RuntimeException {

    /**
     * Construct a new {@link JWTVerificationException}.
     *
     * @param message the exception message
     */
    public JWTVerificationException(String message) {
        this(message, null);
    }

    /**
     * Construct a new {@link JWTVerificationException} wrapping an exception containing the original cause.
     *
     * @param message the exception message
     * @param cause   the {@link Throwable} that originally caused the issue
     */
    public JWTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
