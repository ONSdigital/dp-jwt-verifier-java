package com.github.onsdigital.exceptions;

public class JWTTokenExpiredException extends RuntimeException {
    public JWTTokenExpiredException(String message) {
        this(message, null);
    }

    public JWTTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
