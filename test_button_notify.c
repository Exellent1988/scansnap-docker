/*
 * Unit tests for button_notify (fixtures from scansnap_org_*.pcapng).
 */
#include "button_notify.h"

#include <stdio.h>
#include <string.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t max) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > max)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

static int tests_run;
static int tests_failed;

static void expect_bool(const char *name, bool got, bool want) {
    tests_run++;
    if (got != want) {
        tests_failed++;
        fprintf(stderr, "FAIL %s: got %d want %d\n", name, got, want);
    }
}

static void expect_u32(const char *name, uint32_t got, uint32_t want) {
    tests_run++;
    if (got != want) {
        tests_failed++;
        fprintf(stderr, "FAIL %s: got %u want %u\n", name, got, want);
    }
}

/* scansnap_org_button_test.pcapng — button press ~10s */
static const char *FIXTURE_BUTTON_9 =
    "0000003056454e5300000001000000000900000000000000000000000000000000000000000000000000000000000000";

/* Second button press ~22s */
static const char *FIXTURE_BUTTON_10 =
    "0000003056454e5300000001000000000a00000000000000000000000000000000000000000000000000000000000000";

/* scansnap_org_sbutton.pcapng — periodic idle burst, counter 2 */
static const char *FIXTURE_IDLE_2 =
    "0000003056454e5300000001000000000200000000000000000000000000000000000000000000000000000000000000";

/* Broadcast discovery (53220 style): type 0x21 at offset 8 — not a button notify */
static const char *FIXTURE_BROADCAST =
    "0000003056454e5300000021000000000000000000000000000000000000000000000000000000000000000000000000";

int main(void) {
    uint8_t pkt[BUTTON_NOTIFY_LEN];

    if (hex_decode(FIXTURE_BUTTON_9, pkt, sizeof(pkt)) != BUTTON_NOTIFY_LEN)
        return 1;
    expect_bool("button9 valid", button_notify_valid(pkt, BUTTON_NOTIFY_LEN), true);
    expect_u32("button9 counter", button_notify_counter(pkt, BUTTON_NOTIFY_LEN), 9);

    if (hex_decode(FIXTURE_BUTTON_10, pkt, sizeof(pkt)) != BUTTON_NOTIFY_LEN)
        return 1;
    expect_u32("button10 counter", button_notify_counter(pkt, BUTTON_NOTIFY_LEN), 10);

    if (hex_decode(FIXTURE_IDLE_2, pkt, sizeof(pkt)) != BUTTON_NOTIFY_LEN)
        return 1;
    expect_bool("idle2 valid", button_notify_valid(pkt, BUTTON_NOTIFY_LEN), true);
    expect_u32("idle2 counter", button_notify_counter(pkt, BUTTON_NOTIFY_LEN), 2);

    if (hex_decode(FIXTURE_BROADCAST, pkt, sizeof(pkt)) != BUTTON_NOTIFY_LEN)
        return 1;
    expect_bool("broadcast not notify", button_notify_valid(pkt, BUTTON_NOTIFY_LEN), false);

    expect_bool("short packet", button_notify_valid(pkt, 16), false);
    expect_u32("invalid counter", button_notify_counter(pkt, 16), 0);

    expect_bool("new after 9", button_notify_counter_is_new(9, 10), true);
    expect_bool("duplicate 9", button_notify_counter_is_new(9, 9), false);
    expect_bool("first event", button_notify_counter_is_new(0, 9), true);
    expect_bool("regress", button_notify_counter_is_new(10, 9), false);

    if (tests_failed == 0) {
        fprintf(stderr, "test_button_notify: %d passed\n", tests_run);
        return 0;
    }
    fprintf(stderr, "test_button_notify: %d failed / %d run\n", tests_failed, tests_run);
    return 1;
}
