/*
 * FILE:      src/test/java/com/kwtsms/keycloak/HourlyCapTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4; rewritten onyx-fixes #1176
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for the server-side hourly SMS caps (per user, per realm) against a fake store with an
 *            atomic putIfAbsent and expiry, including parallel callers and a failing store.
 * WHY:       2026-11-09 23:37 +03 (onyx-fixes #1176, K1, K2, K3): the cap moved from a user attribute to Keycloak's
 *            SingleUseObjectProvider; its rules must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class HourlyCapTest {

    /** Start of a clock hour (1_800_000_000 is not one; this is 500_000 * 3600). */
    private static final long HOUR = 1_800_000_000L - Math.floorMod(1_800_000_000L, 3600L);

    /** Fake SingleUseObjectProvider: atomic claim, entries expire, a clock the test moves. */
    static final class FakeStore implements HourlyCap.Store {
        final ConcurrentHashMap<String, Long> claims = new ConcurrentHashMap<>();
        final ConcurrentHashMap<String, String> hints = new ConcurrentHashMap<>();
        final AtomicInteger claimCalls = new AtomicInteger();
        volatile long now;

        FakeStore(long now) {
            this.now = now;
        }

        @Override
        public boolean claim(String key, long lifespanSeconds) {
            assertTrue(lifespanSeconds > 0, "lifespan must be positive");
            assertFalse(key.endsWith(".revoked"));
            claimCalls.incrementAndGet();
            long expires = now + lifespanSeconds;
            boolean[] ours = {false};
            claims.compute(key, (k, old) -> {
                if (old != null && old > now) return old;
                ours[0] = true;
                return expires;
            });
            return ours[0];
        }

        @Override
        public String read(String key) {
            return hints.get(key);
        }

        @Override
        public void write(String key, String value, long lifespanSeconds) {
            hints.put(key, value);
        }
    }

    @Test
    void allowsExactlyMaxThenRefuses() {
        FakeStore st = new FakeStore(HOUR + 10);
        String u = HourlyCap.userScope("r1", "u1");
        for (int i = 0; i < 5; i++) assertTrue(HourlyCap.tryTake(st, u, 5, HOUR + 10 + i));
        assertFalse(HourlyCap.tryTake(st, u, 5, HOUR + 100));
        assertFalse(HourlyCap.tryTake(st, u, 5, HOUR + 3599));
    }

    @Test
    void newClockHourStartsAgainSoTheLockoutIsNeverLongerThanTheWindow() {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        for (int i = 0; i < 3; i++) assertTrue(HourlyCap.tryTake(st, u, 3, HOUR + 3000));
        assertFalse(HourlyCap.tryTake(st, u, 3, HOUR + 3599));
        st.now = HOUR + 3600;
        assertTrue(HourlyCap.tryTake(st, u, 3, HOUR + 3600));
    }

    @Test
    void usersAndRealmsAreSeparate() {
        FakeStore st = new FakeStore(HOUR);
        assertTrue(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u1"), 1, HOUR));
        assertFalse(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u1"), 1, HOUR));
        assertTrue(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u2"), 1, HOUR));
        assertTrue(HourlyCap.tryTake(st, HourlyCap.userScope("r2", "u1"), 1, HOUR));
        assertTrue(HourlyCap.tryTake(st, HourlyCap.realmScope("r1"), 1, HOUR));
        assertFalse(HourlyCap.tryTake(st, HourlyCap.realmScope("r1"), 1, HOUR));
        assertTrue(HourlyCap.tryTake(st, HourlyCap.realmScope("r2"), 1, HOUR));
    }

    @Test
    void realmCeilingAcrossManyUsers() {
        FakeStore st = new FakeStore(HOUR);
        String realm = HourlyCap.realmScope("r1");
        int sent = 0;
        for (int user = 0; user < 300; user++) {
            if (HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u" + user), 5, HOUR)
                    && HourlyCap.tryTake(st, realm, 200, HOUR)) sent++;
        }
        assertEquals(200, sent);
    }

    @Test
    void hintKeepsLookupsShort() {
        FakeStore st = new FakeStore(HOUR);
        String realm = HourlyCap.realmScope("r1");
        for (int i = 0; i < 200; i++) assertTrue(HourlyCap.tryTake(st, realm, 200, HOUR));
        assertEquals(200, st.claimCalls.get());
        st.claimCalls.set(0);
        assertFalse(HourlyCap.tryTake(st, realm, 200, HOUR));
        assertEquals(0, st.claimCalls.get());
    }

    @Test
    void lostOrBrokenHintNeverGivesExtraSms() {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        for (int i = 0; i < 4; i++) assertTrue(HourlyCap.tryTake(st, u, 4, HOUR));
        st.hints.clear();
        assertFalse(HourlyCap.tryTake(st, u, 4, HOUR));
        st.hints.replaceAll((k, v) -> "junk");
        assertFalse(HourlyCap.tryTake(st, u, 4, HOUR));
        st.hints.replaceAll((k, v) -> "-7");
        assertFalse(HourlyCap.tryTake(st, u, 4, HOUR));
    }

    @Test
    void loweringTheLimitMidHourCountsWhatWasSent() {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        for (int i = 0; i < 10; i++) assertTrue(HourlyCap.tryTake(st, u, 50, HOUR));
        assertFalse(HourlyCap.tryTake(st, u, 5, HOUR));
        assertTrue(HourlyCap.tryTake(st, u, 11, HOUR));
    }

    @Test
    void parallelLoginsNeverPassTheCap() throws Exception {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        AtomicInteger granted = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 32; t++) {
            Thread th = new Thread(() -> {
                try {
                    go.await();
                } catch (InterruptedException e) {
                    return;
                }
                if (HourlyCap.tryTake(st, u, 5, HOUR)) granted.incrementAndGet();
            });
            threads.add(th);
            th.start();
        }
        go.countDown();
        for (Thread th : threads) th.join();
        assertEquals(5, granted.get());
    }

    @Test
    void storeFailurePropagatesSoTheCallerFailsClosed() {
        HourlyCap.Store broken = new HourlyCap.Store() {
            @Override
            public boolean claim(String key, long lifespanSeconds) {
                throw new IllegalStateException("cache down");
            }

            @Override
            public String read(String key) {
                return null;
            }

            @Override
            public void write(String key, String value, long lifespanSeconds) {
            }
        };
        assertThrows(IllegalStateException.class,
                () -> HourlyCap.tryTake(broken, HourlyCap.userScope("r1", "u1"), 5, HOUR));
    }

    @Test
    void zeroOrNegativeMaxAllowsNothing() {
        FakeStore st = new FakeStore(HOUR);
        assertFalse(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u1"), 0, HOUR));
        assertEquals(0, st.claimCalls.get());
    }

    @Test
    void secondsLeftIsWithinTheWindow() {
        assertEquals(3600, HourlyCap.secondsLeft(HOUR));
        assertEquals(1, HourlyCap.secondsLeft(HOUR + 3599));
        assertEquals(3000, HourlyCap.secondsLeft(HOUR + 600));
    }
}
