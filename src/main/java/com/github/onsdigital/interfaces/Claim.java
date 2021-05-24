package com.github.onsdigital.interfaces;

import com.github.onsdigital.exceptions.JWTDecodeException;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Claim class holds value in generic way - may be recovered in many forms.
 */
public interface Claim {

    boolean isNull();

    Boolean asBoolean();

    Integer asInt();

    Long asLong();

    Double asDouble();

    String asString();

    String[] asStringArray();

    Date asDate();

    <T> T[] asArray(Class<T> tClazz) throws JWTDecodeException;

    <T> List<T> asList(Class<T> tClazz) throws JWTDecodeException;

    Map<String, Object> asMap() throws JWTDecodeException;

    <T> T as(Class<T> tClazz) throws JWTDecodeException;

}
