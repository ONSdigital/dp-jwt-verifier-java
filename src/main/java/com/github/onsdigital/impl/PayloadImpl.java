package com.github.onsdigital.impl;

import com.github.onsdigital.interfaces.Claim;
import com.github.onsdigital.interfaces.Payload;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;

import java.io.Serializable;
import java.util.*;

import static com.github.onsdigital.impl.JsonNodeClaim.extractClaim;

/**
 * Decoder of string JSON Web Tokens into their POJO representations.
 *
 * @see Payload
 * <p>
 * This class is thread-safe.
 */
class PayloadImpl implements Payload, Serializable {

    private static final long serialVersionUID = 1659021498824562311L;
    private final Map<String, JsonNode> tree;
    private final ObjectReader objectReader;

    PayloadImpl(Map<String, JsonNode> tree, ObjectReader objectReader) {
        this.tree = tree != null ? Collections.unmodifiableMap(tree) : Collections.<String, JsonNode>emptyMap();
        this.objectReader = objectReader;
    }

    Map<String, JsonNode> getTree() {
        return tree;
    }

    @Override
    public Claim getClaim(String name) {
        return extractClaim(name, tree, objectReader);
    }
}
