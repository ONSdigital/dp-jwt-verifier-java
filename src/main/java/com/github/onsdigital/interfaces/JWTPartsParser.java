package com.github.onsdigital.interfaces;

import  com.github.onsdigital.exceptions.JWTDecodeException;

/**
 * JWTPartsParser class defines parts of JWT that will be converted to Object representation instance.
 */
public interface JWTPartsParser {

    Payload parsePayload(String json) throws JWTDecodeException;

    Header parseHeader(String json) throws JWTDecodeException;

}
