package com.example.oauthserver.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.time.Duration;

/**
 * Jackson mixin for Duration serialization/deserialization
 */
public abstract class DurationMixin {

    @JsonCreator
    public static Duration of(String value) {
        return Duration.parse(value);
    }

    @JsonValue
    public abstract String toString();
}
