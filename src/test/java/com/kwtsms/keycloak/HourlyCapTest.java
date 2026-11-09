/*
 * FILE:      src/test/java/com/kwtsms/keycloak/HourlyCapTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for the per-user hourly SMS cap: trimming old, future and corrupt timestamps, and the limit.
 * WHY:       The security rules of the SMS code step must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HourlyCapTest {

    private static final long NOW = 1_800_000_000L;

    @Test
    void dropsOlderThanOneHourFutureAndGarbage() {
        List<String> stored = Arrays.asList(
                Long.toString(NOW - 3600),   // exactly one hour old: out
                Long.toString(NOW - 3599),   // in
                Long.toString(NOW - 10),     // in
                Long.toString(NOW + 60),     // future: out
                "abc", null, " " + (NOW - 5) + " ");
        List<Long> recent = HourlyCap.trim(stored, NOW);
        assertEquals(Arrays.asList(NOW - 3599, NOW - 10, NOW - 5), recent);
    }

    @Test
    void nullOrEmptyIsZero() {
        assertTrue(HourlyCap.trim(null, NOW).isEmpty());
        assertTrue(HourlyCap.trim(List.of(), NOW).isEmpty());
    }

    @Test
    void capAllowsUpToMax() {
        List<Long> four = Arrays.asList(1L, 2L, 3L, 4L);
        List<Long> five = Arrays.asList(1L, 2L, 3L, 4L, 5L);
        assertTrue(HourlyCap.allowed(four, 5));
        assertFalse(HourlyCap.allowed(five, 5));
    }

    @Test
    void roundTripToStrings() {
        List<String> s = HourlyCap.toStrings(Arrays.asList(NOW - 1, NOW));
        assertEquals(Arrays.asList(Long.toString(NOW - 1), Long.toString(NOW)), s);
        assertEquals(2, HourlyCap.trim(s, NOW).size());
    }
}
