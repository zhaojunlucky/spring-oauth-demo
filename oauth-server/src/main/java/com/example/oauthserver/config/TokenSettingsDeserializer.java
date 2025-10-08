package com.example.oauthserver.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class TokenSettingsDeserializer extends JsonDeserializer<Map<String, Object>> {

    @Override
    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);
        Map<String, Object> settings = new HashMap<>();
        
        node.fields().forEachRemaining(entry -> {
            String key = entry.getKey();
            JsonNode valueNode = entry.getValue();
            
            if (key.contains("TimeToLive") && valueNode.isTextual()) {
                // Parse Duration from ISO-8601 string
                try {
                    settings.put(key, Duration.parse(valueNode.asText()));
                } catch (Exception e) {
                    // If parsing fails, treat as regular object
                    settings.put(key, valueNode.asText());
                }
            } else if (valueNode.isTextual()) {
                settings.put(key, valueNode.asText());
            } else if (valueNode.isBoolean()) {
                settings.put(key, valueNode.asBoolean());
            } else if (valueNode.isNumber()) {
                if (key.contains("TimeToLive")) {
                    // Convert number to Duration (assuming seconds)
                    settings.put(key, Duration.ofSeconds(valueNode.asLong()));
                } else {
                    settings.put(key, valueNode.asLong());
                }
            } else {
                // For complex objects, use default deserialization
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    Object value = mapper.treeToValue(valueNode, Object.class);
                    settings.put(key, value);
                } catch (Exception e) {
                    settings.put(key, valueNode.toString());
                }
            }
        });
        
        return settings;
    }
}
