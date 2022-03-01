package com.github.onsdigital.exceptions;

/**
 * JWTVerificationException is the exception used for cases when decoding the JWT or its claims payload fails.
 */
public class JWTDecodeException extends RuntimeException {

    /**
     * Construct a new {@link JWTDecodeException}.
     *
     * @param message the exception message
     */
    public JWTDecodeException(String message) {
        this(message, null);
    }

    /**
     * Construct a new {@link JWTDecodeException} wrapping an exception containing the original cause.
     *
     * @param message the exception message
     * @param cause   the {@link Throwable} that originally caused the issue
     */
    public JWTDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
