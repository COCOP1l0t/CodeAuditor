CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wextra -D_GNU_SOURCE
CPPFLAGS += -Iinclude
LDFLAGS ?=

BUILD     := build
BIN       := $(BUILD)/minisvc
ASAN_BIN  := $(BUILD)/minisvc-asan

SRC       := $(wildcard src/*.c)
OBJ       := $(patsubst src/%.c,$(BUILD)/obj/%.o,$(SRC))
ASAN_OBJ  := $(patsubst src/%.c,$(BUILD)/asan/%.o,$(SRC))

.PHONY: all asan clean

all: $(BIN)

asan: $(ASAN_BIN)

$(BIN): $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

$(ASAN_BIN): $(ASAN_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $^ -o $@ $(LDFLAGS)

$(BUILD)/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/asan/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -c $< -o $@

clean:
	rm -rf $(BUILD)
