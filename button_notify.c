#include "button_notify.h"

#include <string.h>

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool button_notify_valid(const uint8_t *data, size_t len) {
    if (!data || len < BUTTON_NOTIFY_LEN)
        return false;
    if (be32(data) != BUTTON_NOTIFY_LEN)
        return false;
    if (memcmp(data + 4, "VENS", 4) != 0)
        return false;
    /* Callback notify uses 0x01; broadcast discovery on 53220 uses 0x21. */
    if (be32(data + 8) != 1)
        return false;
    return true;
}

uint32_t button_notify_counter(const uint8_t *data, size_t len) {
    if (!button_notify_valid(data, len))
        return 0;
  /* Observed on wire: counter is little-endian at offset 16 (e.g. 09 00 00 00). */
    return le32(data + 16);
}

bool button_notify_counter_is_new(uint32_t last_seen, uint32_t counter) {
    if (counter == 0)
        return false;
    return last_seen == 0 || counter > last_seen;
}
