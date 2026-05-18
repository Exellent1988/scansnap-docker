CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -Werror -Wformat-security -fstack-protector-strong -O2 -D_GNU_SOURCE
LDFLAGS = -lpthread
TARGET = scansnap
TEST_NOTIFY = test_button_notify

$(TARGET): scansnap.c button_notify.c button_notify.h
	$(CC) $(CFLAGS) -o $@ scansnap.c button_notify.c $(LDFLAGS)

$(TEST_NOTIFY): test_button_notify.c button_notify.c
	$(CC) $(CFLAGS) -o $@ test_button_notify.c button_notify.c

test: $(TEST_NOTIFY)
	./$(TEST_NOTIFY)
	@if command -v python3 >/dev/null 2>&1; then \
		python3 scripts/verify_button_pcap.py; \
	else \
		echo "python3 not found, skipping verify_button_pcap.py"; \
	fi

clean:
	rm -f $(TARGET) $(TEST_NOTIFY)

.PHONY: clean test
