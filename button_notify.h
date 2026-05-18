/*
 * Scanner button callback notifications (UDP, 48-byte VENS packets to port 55265).
 * Observed in scansnap_org_button_test.pcapng; see PROTOCOL callback port 0xd7e1.
 */
#ifndef BUTTON_NOTIFY_H
#define BUTTON_NOTIFY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUTTON_NOTIFY_LEN 48
#define BUTTON_CALLBACK_PORT 55265

/* True for 48-byte scanner→client notify payloads (not broadcast discovery). */
bool button_notify_valid(const uint8_t *data, size_t len);

/* Event/sequence counter (little-endian u32 at offset 16); 0 if invalid. */
uint32_t button_notify_counter(const uint8_t *data, size_t len);

/* True when counter strictly increases (first event: last_seen may be 0). */
bool button_notify_counter_is_new(uint32_t last_seen, uint32_t counter);

#endif
