CC ?= gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Werror -pedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now
ROOT ?= ../../..
OUT ?= build

all: $(OUT)/kos-boot

$(OUT)/kos-boot: kos-boot.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) kos-boot.c -o $@ $(LDFLAGS) -lcrypto

# Write the manifest for the core as it is now. Do this when building the signed pre-boot image;
# the manifest then lives inside that image, not beside the files it vouches for.
seal:
	@mkdir -p $(OUT)
	cd $(ROOT) && find kos bin -type f ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs sha256sum > $(abspath $(OUT))/CORE.sha256

clean:
	rm -rf $(OUT)
.PHONY: all seal clean
