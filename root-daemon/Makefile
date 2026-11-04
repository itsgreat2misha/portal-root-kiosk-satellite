# Build portal-root-daemon (aarch64, Android API 28).
#
#   make            # -> portal-root-daemon
#
# The binary is dynamically linked against the device's own libc, like every
# other provisioner payload; it must run on the target's Android 9 / API 28.

include ../android-env.mk

API ?= 28
CC := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang

CFLAGS := -O2 -Wall -Wextra -Werror -fPIE -pie -std=c11 -D_GNU_SOURCE

portal-root-daemon: src/portal-root-daemon.c
	$(CC) $(CFLAGS) -o $@ src/portal-root-daemon.c

clean:
	rm -f portal-root-daemon

.PHONY: clean
