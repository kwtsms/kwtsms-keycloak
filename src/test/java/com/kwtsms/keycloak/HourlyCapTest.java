/*
 * FILE:      src/test/java/com/kwtsms/keycloak/HourlyCapTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4; rewritten onyx-fixes #1176
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for the server-side hourly SMS caps (per user, per realm) against a fake store with an
 *            atomic putIfAbsent and expiry, including parallel callers and a failing store.
 * WHY:       2026-11-09 23:37 +03 (onyx-fixes #1176, K1, K2, K3): the cap moved from a user attribute to Keycloak's
 *            SingleUseObjectProvider; its rules must hold without a running Keycloak; no network.
 *            2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2): per-IP throttle, takeAll in order, and slot release after a failed send.
 *            2026-11-10 00:07 +03 (onyx-fixes #1176, C3): IP key normalization (IPv6 /64, IPv4-mapped, unparseable).
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
    // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): no longer final, two tests override one method to fail.
    static class FakeStore implements HourlyCap.Store {
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

        // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2)
        @Override
        public void release(String key) {
            claims.remove(key);
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

            @Override
            public void release(String key) {
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

    // 2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2): per-IP throttle and slot release.

    private static String[] scopes(String user, String ip) {
        return new String[] {HourlyCap.userScope("r1", user), HourlyCap.ipScope("r1", ip), HourlyCap.realmScope("r1")};
    }

    @Test
    void ipScopesAreSeparateAndAMissingIpSharesOneBucket() {
        assertNotEquals(HourlyCap.ipScope("r1", "10.0.0.1"), HourlyCap.ipScope("r1", "10.0.0.2"));
        assertNotEquals(HourlyCap.ipScope("r1", "10.0.0.1"), HourlyCap.ipScope("r2", "10.0.0.1"));
        assertEquals(HourlyCap.ipScope("r1", null), HourlyCap.ipScope("r1", ""));
        assertFalse(HourlyCap.ipScope("r1", "::1").endsWith(".revoked"));
    }

    // 2026-11-10 00:07 +03 (onyx-fixes #1176, C3): IPv4 as is, IPv6 by /64, IPv4-mapped as IPv4, junk as "unknown".
    @Test
    void ipKeyNormalizesAddresses() {
        assertEquals("203.0.113.7", HourlyCap.ipKey("203.0.113.7"));
        assertEquals("203.0.113.7", HourlyCap.ipKey(" 203.0.113.7 "));
        assertEquals("2001:db8:1:2::/64", HourlyCap.ipKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        assertEquals(HourlyCap.ipKey("2001:db8:1:2::1"), HourlyCap.ipKey("2001:0db8:0001:0002:ffff:0:0:9"));
        assertEquals("2001:db8:1:2::/64", HourlyCap.ipKey("[2001:db8:1:2::1]"));
        assertEquals("2001:db8:1:2::/64", HourlyCap.ipKey("2001:db8:1:2::1%eth0"));
        assertNotEquals(HourlyCap.ipKey("2001:db8:1:2::1"), HourlyCap.ipKey("2001:db8:1:3::1"));
        assertEquals("0:0:0:0::/64", HourlyCap.ipKey("::1"));
        assertEquals("203.0.113.7", HourlyCap.ipKey("::ffff:203.0.113.7"));
        assertEquals("203.0.113.7", HourlyCap.ipKey("::ffff:cb00:7107"));
        assertEquals("unknown", HourlyCap.ipKey(null));
        assertEquals("unknown", HourlyCap.ipKey(""));
        assertEquals("unknown", HourlyCap.ipKey("unknown"));
        assertEquals("unknown", HourlyCap.ipKey("example.com"));
        assertEquals("unknown", HourlyCap.ipKey("256.1.1.1"));
        assertEquals("unknown", HourlyCap.ipKey("127.1"));
        assertEquals("unknown", HourlyCap.ipKey("2001:db8::1::2"));
        assertEquals("unknown", HourlyCap.ipKey("12345::1"));
        assertEquals("unknown", HourlyCap.ipKey("2001:db8::zz"));
        assertEquals(HourlyCap.ipScope("r1", "2001:db8:1:2::5"), HourlyCap.ipScope("r1", "2001:db8:1:2::6"));
    }

    @Test
    void oneIpWithManyStolenPasswordsCannotDrainTheRealm() {
        FakeStore st = new FakeStore(HOUR);
        int[] max = {5, 20, 200};
        int sent = 0;
        for (int user = 0; user < 300; user++) {
            List<String> taken = new ArrayList<>();
            if (HourlyCap.takeAll(st, scopes("u" + user, "203.0.113.9"), max, HOUR, taken) == -1) sent++;
        }
        assertEquals(20, sent);
        // The realm still has 180 slots for everyone else.
        int others = 0;
        for (int user = 0; user < 300; user++) {
            List<String> taken = new ArrayList<>();
            if (HourlyCap.takeAll(st, scopes("v" + user, "198.51.100." + (user % 250)), max, HOUR, taken) == -1) {
                others++;
            }
        }
        assertEquals(180, others);
    }

    @Test
    void takeAllReportsTheFullScopeAndKeepsNoSlotOfARefusedSms() {
        FakeStore st = new FakeStore(HOUR);
        int[] max = {5, 2, 200};
        for (int i = 0; i < 2; i++) assertEquals(-1, HourlyCap.takeAll(st, scopes("u" + i, "ip"), max, HOUR,
                new ArrayList<>()));
        List<String> taken = new ArrayList<>();
        assertEquals(1, HourlyCap.takeAll(st, scopes("u9", "ip"), max, HOUR, taken));
        assertTrue(taken.isEmpty());
        // u9's user slot was given back: all 5 are still free for u9 from another address.
        for (int i = 0; i < 5; i++) assertTrue(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u9"), 5, HOUR));
        // The realm slot was never taken: 2 of 200 used.
        int realmLeft = 0;
        while (HourlyCap.tryTake(st, HourlyCap.realmScope("r1"), 200, HOUR)) realmLeft++;
        assertEquals(198, realmLeft);
    }

    @Test
    void failedSendReleasesUserIpAndRealmSlots() {
        FakeStore st = new FakeStore(HOUR);
        int[] max = {1, 1, 1};
        List<String> taken = new ArrayList<>();
        assertEquals(-1, HourlyCap.takeAll(st, scopes("u1", "ip"), max, HOUR, taken));
        assertEquals(3, taken.size());
        assertEquals(0, HourlyCap.takeAll(st, scopes("u1", "ip"), max, HOUR, new ArrayList<>()));
        // the send failed (kwtSMS down): give the slots back
        assertEquals(0, HourlyCap.releaseAll(st, taken, HOUR));
        assertTrue(taken.isEmpty());
        assertTrue(st.claims.isEmpty());
        assertEquals(-1, HourlyCap.takeAll(st, scopes("u1", "ip"), max, HOUR, new ArrayList<>()));
    }

    @Test
    void manyFailedSendsNeverLockTheUserOut() {
        FakeStore st = new FakeStore(HOUR);
        int[] max = {5, 20, 200};
        for (int attempt = 0; attempt < 500; attempt++) {
            List<String> taken = new ArrayList<>();
            assertEquals(-1, HourlyCap.takeAll(st, scopes("u1", "ip"), max, HOUR, taken), "attempt " + attempt);
            HourlyCap.releaseAll(st, taken, HOUR);
        }
        for (int i = 0; i < 5; i++) assertTrue(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u1"), 5, HOUR));
        assertFalse(HourlyCap.tryTake(st, HourlyCap.userScope("r1", "u1"), 5, HOUR));
    }

    @Test
    void releasingALowSlotLowersTheHintSoItIsFoundAgain() {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        String first = HourlyCap.take(st, u, 3, HOUR);
        assertNotNull(HourlyCap.take(st, u, 3, HOUR));
        assertNotNull(HourlyCap.take(st, u, 3, HOUR));
        assertNull(HourlyCap.take(st, u, 3, HOUR));
        HourlyCap.release(st, first, HOUR);
        assertEquals(first, HourlyCap.take(st, u, 3, HOUR));
        assertNull(HourlyCap.take(st, u, 3, HOUR));
    }

    @Test
    void releaseNeverGivesMoreThanMax() {
        FakeStore st = new FakeStore(HOUR);
        String u = HourlyCap.userScope("r1", "u1");
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < 4; i++) keys.add(HourlyCap.take(st, u, 4, HOUR));
        HourlyCap.release(st, keys.get(3), HOUR);
        HourlyCap.release(st, keys.get(1), HOUR);
        assertNotNull(HourlyCap.take(st, u, 4, HOUR));
        assertNotNull(HourlyCap.take(st, u, 4, HOUR));
        assertNull(HourlyCap.take(st, u, 4, HOUR));
        assertEquals(4, st.claims.size());
    }

    @Test
    void releaseErrorsAreCountedNotThrown() {
        FakeStore st = new FakeStore(HOUR) {
            @Override
            public void release(String key) {
                throw new IllegalStateException("cache down");
            }
        };
        List<String> taken = new ArrayList<>();
        assertEquals(-1, HourlyCap.takeAll(st, scopes("u1", "ip"), new int[] {5, 20, 200}, HOUR, taken));
        assertEquals(3, HourlyCap.releaseAll(st, taken, HOUR));
        assertTrue(taken.isEmpty());
    }

    @Test
    void storeErrorInTakeAllReleasesWhatWasTakenAndPropagates() {
        FakeStore st = new FakeStore(HOUR) {
            @Override
            public boolean claim(String key, long lifespanSeconds) {
                if (key.contains(":realm:")) throw new IllegalStateException("cache down");
                return super.claim(key, lifespanSeconds);
            }
        };
        List<String> taken = new ArrayList<>();
        assertThrows(IllegalStateException.class,
                () -> HourlyCap.takeAll(st, scopes("u1", "ip"), new int[] {5, 20, 200}, HOUR, taken));
        assertTrue(taken.isEmpty());
        assertTrue(st.claims.isEmpty());
    }
}
