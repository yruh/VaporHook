CXX ?= g++
CC ?= gcc
AR ?= ar

BUILD_DIR ?= build/native
DEPS_ROOT ?= build/_deps/zydis
ARCH_FLAGS ?=

CPPFLAGS := -Iinclude -isystem $(DEPS_ROOT)/amalgamated-dist \
	-DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD
CXXFLAGS := -std=c++20 -O2 -g -fPIC -fvisibility=hidden -Wall -Wextra -Wpedantic -Werror
CFLAGS := -std=c11 -O2 -g -fPIC -fvisibility=hidden -Wall -Wno-unused-const-variable
DEPFLAGS := -MMD -MP

LIBRARY := $(BUILD_DIR)/libvaporhook.a
ENGINE_OBJECT := $(BUILD_DIR)/vaporhook.o
ZYDIS_OBJECT := $(BUILD_DIR)/zydis.o
TEST_BINARY := $(BUILD_DIR)/vaporhook_tests
FIXTURE_LIBRARY := $(BUILD_DIR)/libvaporhook_fixture.so
DEPS_STAMP := $(DEPS_ROOT)/.ready

.PHONY: all deps lib test test32 check clean

all: check

deps: $(DEPS_STAMP)

$(DEPS_STAMP): scripts/fetch-dependencies.sh
	./scripts/fetch-dependencies.sh "$(DEPS_ROOT)"

$(ENGINE_OBJECT): src/vaporhook.cpp include/vaporhook/vaporhook.h $(DEPS_STAMP)
	@mkdir -p $(dir $@)
	$(CXX) $(ARCH_FLAGS) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(ZYDIS_OBJECT): $(DEPS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(ARCH_FLAGS) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) \
		-c $(DEPS_ROOT)/amalgamated-dist/Zydis.c -o $@

$(LIBRARY): $(ENGINE_OBJECT) $(ZYDIS_OBJECT)
	$(AR) rcs $@ $^

lib: $(LIBRARY)

$(FIXTURE_LIBRARY): tests/fixtures/hook_fixture.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(ARCH_FLAGS) -std=c++20 -O2 -g -fPIC -shared -Wall -Wextra -Werror $< -o $@

$(TEST_BINARY): tests/test_vaporhook.cpp $(LIBRARY) $(FIXTURE_LIBRARY)
	$(CXX) $(ARCH_FLAGS) $(CPPFLAGS) $(CXXFLAGS) \
		-DVAPORHOOK_FIXTURE_PATH=\"$(abspath $(FIXTURE_LIBRARY))\" \
		$< $(LIBRARY) -Wl,--wrap=mprotect -ldl -pthread -o $@

test: $(TEST_BINARY)
	$(TEST_BINARY)

test32:
	$(MAKE) BUILD_DIR=build/32 ARCH_FLAGS=-m32 test

check: test test32

clean:
	rm -rf build/native build/32

-include $(ENGINE_OBJECT:.o=.d) $(ZYDIS_OBJECT:.o=.d)
