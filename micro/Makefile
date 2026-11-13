CC ?= gcc
CORE = -std=c99 -pedantic -Os -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector \
       -fno-tree-loop-distribute-patterns -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections
SAN  = -std=gnu99 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -DNO_STACKTEST

all: build/kmicro.o build/kos-micro

build/kmicro.o: kmicro.c kmicro.h
	@mkdir -p build
	$(CC) $(CORE) -c kmicro.c -o $@

build/kos-micro: host_main.c apps.h build/kmicro.o
	$(CC) -std=c99 -Wall -Wextra -Werror host_main.c build/kmicro.o -o $@

build/test: test.c apps.h build/kmicro.o
	$(CC) -std=gnu99 -O1 -Wall -Wextra -Werror test.c build/kmicro.o -o $@

build/test-san: test.c apps.h kmicro.c kmicro.h
	$(CC) $(SAN) test.c kmicro.c -o $@

check: build/kmicro.o build/test build/test-san
	@if nm -u build/kmicro.o | awk '{print $$2}' | grep -v '^hal_'; then echo "FAIL: core needs more than hal_*"; exit 1; fi
	@echo "core links against only hal_*: ok"
	@size build/kmicro.o
	./build/test
	./build/test-san

clean:
	rm -rf build
.PHONY: all check clean
