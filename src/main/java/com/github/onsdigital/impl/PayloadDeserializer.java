package com.github.onsdigital.impl;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.interfaces.Payload;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.*;

/**
 * Jackson deserializer implementation for converting from JWT Payload parts.
 *
 * @see JWTParser
 * <p>
 * This class is thread-safe.
 */
class PayloadDeserializer extends StdDeserializer<Payload> {

    private final ObjectReader objectReader;

    PayloadDeserializer(ObjectReader reader) {
        this(null, reader);
    }

    private PayloadDeserializer(Class<?> vc, ObjectReader reader) {
        super(vc);

        this.objectReader = reader;
    }

    @Override
    public Payload deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Payload's JSON resulted on a Null map");
        }

        return new PayloadImpl(tree, objectReader);
    }

    List<String> getStringOrArray(Map<String, JsonNode> tree, String claimName) throws JWTDecodeException {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !(node.isArray() || node.isTextual())) {
            return null;
        }
        if (node.isTextual() && !node.asText().isEmpty()) {
            return Collections.singletonList(node.asText());
        }

        List<String> list = new ArrayList<>(node.size());
        for (int i = 0; i < node.size(); i++) {
            try {
                list.add(objectReader.treeToValue(node.get(i), String.class));
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to String", e);
            }
        }
        return list;
    }

    Date getDateFromSeconds(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.canConvertToLong()) {
            throw new JWTDecodeException(String.format("The claim '%s' contained a non-numeric date value.", claimName));
        }
        final long ms = node.asLong() * 1000;
        return new Date(ms);
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asText(null);
    }
}
