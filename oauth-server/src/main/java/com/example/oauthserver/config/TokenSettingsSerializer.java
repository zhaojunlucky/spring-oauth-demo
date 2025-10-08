package com.example.oauthserver.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

public class TokenSettingsSerializer extends JsonSerializer<Map<String, Object>> {

    @Override
    public void serialize(Map<String, Object> settings, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeStartObject();
        
        for (Map.Entry<String, Object> entry : settings.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            gen.writeFieldName(key);
            
            if (value instanceof Duration) {
                // Serialize Duration as ISO-8601 string
                gen.writeString(((Duration) value).toString());
            } else {
                gen.writeObject(value);
            }
        }
        
        gen.writeEndObject();
    }
}
