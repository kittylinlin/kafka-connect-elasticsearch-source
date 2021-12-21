package com.github.dariobalinzo.filter;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.Set;
import java.util.HashMap;

public class MapCastFilter implements DocumentFilter {
    private final Set<String> fieldsToCast;
    private final JsonFilterVisitor visitor;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MapCastFilter(Set<String> fieldsToCast) {
        this.fieldsToCast = fieldsToCast;
        visitor = new JsonFilterVisitor(this::checkIfMapCastNeeded);
    }

    @Override
    public void filter(Map<String, Object> document) {
        visitor.visit(document);
    }

    private Object checkIfMapCastNeeded(String key, Object value) {
        if (fieldsToCast.contains(key)) {
            return castToMap(value);
        } else {
            return value;
        }
    }

    private Object castToMap(Object value) {
        try {
            return objectMapper.readValue((String)value, HashMap.class);
        } catch (Exception e) {
            return value;
        }
    }
}
