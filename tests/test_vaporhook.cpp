#include "vaporhook/vaporhook.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef VAPORHOOK_FIXTURE_PATH
#error "VAPORHOOK_FIXTURE_PATH must name the test fixture"
#endif

extern "C" int __real_mprotect(void *address, std::size_t length, int protection);

namespace {

std::atomic<int> wrapped_mprotect_calls{0};
std::atomic<int> wrapped_mprotect_failure{0};
std::atomic<bool> wrapped_mprotect_monitor{false};
std::atomic<bool> wrapped_mprotect_saw_rwx{false};

} // namespace

extern "C" int __wrap_mprotect(void *address, std::size_t length, int protection) {
    if (wrapped_mprotect_monitor.load(std::memory_order_acquire) &&
        (protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        wrapped_mprotect_saw_rwx.store(true, std::memory_order_release);
    }
    const int failure = wrapped_mprotect_failure.load(std::memory_order_acquire);
    if (failure != 0) {
        const int call = wrapped_mprotect_calls.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (call == failure) {
            errno = EACCES;
            return -1;
        }
    }
    return __real_mprotect(address, length, protection);
}

namespace {

int failures = 0;

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << ": " #expression << '\n';      \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

using HookFunction = int (*)(int);

struct MapPermissions {
    bool found{false};
    bool read{false};
    bool write{false};
    bool execute{false};
    std::array<char, 5> raw{};
};

bool permissions_for(const void *address, MapPermissions *result) {
    FILE *file = std::fopen("/proc/self/maps", "r");
    if (file == nullptr) {
        return false;
    }
    const auto needle = reinterpret_cast<std::uintptr_t>(address);
    std::array<char, 4096> line{};
    while (std::fgets(line.data(), static_cast<int>(line.size()), file) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        std::array<char, 5> permissions{};
        if (std::sscanf(line.data(), "%llx-%llx %4s", &start, &end, permissions.data()) != 3) {
            continue;
        }
        if (needle < start || needle >= end) {
            continue;
        }
        result->found = true;
        result->read = permissions[0] == 'r';
        result->write = permissions[1] == 'w';
        result->execute = permissions[2] == 'x';
        result->raw = permissions;
        std::fclose(file);
        return true;
    }
    std::fclose(file);
    return false;
}

bool exact_rx(const MapPermissions &permissions) {
    return permissions.found && permissions.read && !permissions.write && permissions.execute;
}

struct AnonymousFunction {
    void *mapping{nullptr};
    std::size_t size{0};
    HookFunction function{nullptr};
    std::array<std::uint8_t, 16> original{};

    AnonymousFunction() = default;
    AnonymousFunction(const AnonymousFunction &) = delete;
    AnonymousFunction &operator=(const AnonymousFunction &) = delete;

    ~AnonymousFunction() {
        release();
    }

    void release() {
        if (mapping != nullptr) {
            ::munmap(mapping, size);
            mapping = nullptr;
            size = 0;
            function = nullptr;
        }
    }
};

bool make_function(int value, bool rwx, AnonymousFunction *result) {
    const long raw_page_size = ::sysconf(_SC_PAGESIZE);
    const std::size_t page_size = raw_page_size > 0 ? static_cast<std::size_t>(raw_page_size) : 4096;
    void *mapping = ::mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return false;
    }

    std::array<std::uint8_t, 16> code{};
    code.fill(0x90);
    code[0] = 0xB8;
    const std::uint32_t immediate = static_cast<std::uint32_t>(value);
    std::memcpy(code.data() + 1, &immediate, sizeof(immediate));
    code[5] = 0xC3;
    std::memcpy(mapping, code.data(), code.size());
    const int protection = PROT_READ | PROT_EXEC | (rwx ? PROT_WRITE : 0);
    if (::mprotect(mapping, page_size, protection) != 0) {
        ::munmap(mapping, page_size);
        return false;
    }

    result->mapping = mapping;
    result->size = page_size;
    result->function = reinterpret_cast<HookFunction>(mapping);
    result->original = code;
    return true;
}

bool make_code_function(const std::array<std::uint8_t, 16> &code, AnonymousFunction *result) {
    const long raw_page_size = ::sysconf(_SC_PAGESIZE);
    const std::size_t page_size = raw_page_size > 0 ? static_cast<std::size_t>(raw_page_size) : 4096;
    void *mapping = ::mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return false;
    }
    std::memcpy(mapping, code.data(), code.size());
    if (::mprotect(mapping, page_size, PROT_READ | PROT_EXEC) != 0) {
        ::munmap(mapping, page_size);
        return false;
    }
    result->mapping = mapping;
    result->size = page_size;
    result->function = reinterpret_cast<HookFunction>(mapping);
    result->original = code;
    return true;
}

std::atomic<HookFunction> fixture_trampoline{nullptr};

extern "C" int fixture_detour(int value) {
    HookFunction original = fixture_trampoline.load(std::memory_order_acquire);
    return original != nullptr ? original(value) * 3 : -1;
}

extern "C" int detour_one(int) {
    return 1001;
}

extern "C" int detour_two(int) {
    return 1002;
}

void report(const char *operation, vaporhook_engine_t *engine, vaporhook_status_t status) {
    std::cerr << operation << " failed: " << vaporhook_status_string(status) << " ("
              << vaporhook_error_message(engine) << ")\n";
}

void test_api_validation() {
    CHECK(vaporhook_create(nullptr) == VAPORHOOK_ERROR_INVALID_ARGUMENT);

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    CHECK(engine != nullptr);
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_EMPTY);
    CHECK(vaporhook_hook_count(engine) == 0);
    CHECK(vaporhook_install(engine) == VAPORHOOK_ERROR_INVALID_STATE);

    void *trampoline = nullptr;
    CHECK(vaporhook_prepare(engine, nullptr, reinterpret_cast<void *>(detour_one), &trampoline) ==
          VAPORHOOK_ERROR_INVALID_ARGUMENT);
    CHECK(vaporhook_prepare(engine, reinterpret_cast<void *>(detour_one),
                            reinterpret_cast<void *>(detour_one), &trampoline) ==
          VAPORHOOK_ERROR_INVALID_ARGUMENT);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
}

void test_fixture_lifecycle() {
    void *handle = ::dlopen(VAPORHOOK_FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL);
    CHECK(handle != nullptr);
    if (handle == nullptr) {
        std::cerr << ::dlerror() << '\n';
        return;
    }

    void *symbol = ::dlsym(handle, "vaporhook_fixture_target");
    CHECK(symbol != nullptr);
    if (symbol == nullptr) {
        ::dlclose(handle);
        return;
    }
    auto target = reinterpret_cast<HookFunction>(symbol);
    CHECK(target(5) == 12);

    MapPermissions before{};
    CHECK(permissions_for(symbol, &before));
    CHECK(exact_rx(before));

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *raw_trampoline = nullptr;
    const vaporhook_status_t prepared =
        vaporhook_prepare(engine, symbol, reinterpret_cast<void *>(fixture_detour), &raw_trampoline);
    if (prepared != VAPORHOOK_SUCCESS) {
        report("prepare fixture", engine, prepared);
        CHECK(prepared == VAPORHOOK_SUCCESS);
        (void)vaporhook_destroy(engine);
        ::dlclose(handle);
        return;
    }
    CHECK(raw_trampoline != nullptr);
    CHECK(raw_trampoline != symbol);
    CHECK(target(5) == 12);
    fixture_trampoline.store(reinterpret_cast<HookFunction>(raw_trampoline),
                             std::memory_order_release);

    MapPermissions after_prepare{};
    CHECK(permissions_for(symbol, &after_prepare));
    CHECK(exact_rx(after_prepare));
    MapPermissions trampoline_permissions{};
    CHECK(permissions_for(raw_trampoline, &trampoline_permissions));
    CHECK(exact_rx(trampoline_permissions));

    const vaporhook_status_t installed = vaporhook_install(engine);
    if (installed != VAPORHOOK_SUCCESS) {
        report("install fixture", engine, installed);
        CHECK(installed == VAPORHOOK_SUCCESS);
        fixture_trampoline.store(nullptr, std::memory_order_release);
        (void)vaporhook_destroy(engine);
        ::dlclose(handle);
        return;
    }
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_INSTALLED);
    CHECK(target(5) == 36);
    CHECK(reinterpret_cast<HookFunction>(raw_trampoline)(5) == 12);

    MapPermissions installed_permissions{};
    CHECK(permissions_for(symbol, &installed_permissions));
    CHECK(exact_rx(installed_permissions));
    CHECK(std::strcmp(before.raw.data(), installed_permissions.raw.data()) == 0);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_ERROR_INVALID_STATE);

    const vaporhook_status_t uninstalled = vaporhook_uninstall(engine);
    if (uninstalled != VAPORHOOK_SUCCESS) {
        report("uninstall fixture", engine, uninstalled);
    }
    CHECK(uninstalled == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_PREPARED);
    CHECK(target(5) == 12);
    fixture_trampoline.store(nullptr, std::memory_order_release);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
    CHECK(::dlclose(handle) == 0);
}

void test_install_preflight_failure_is_clean() {
    AnonymousFunction first{};
    AnonymousFunction second{};
    AnonymousFunction third{};
    CHECK(make_function(41, false, &first));
    CHECK(make_function(42, false, &second));
    CHECK(make_function(43, false, &third));
    if (first.function == nullptr || second.function == nullptr || third.function == nullptr) {
        return;
    }

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *first_trampoline = nullptr;
    void *second_trampoline = nullptr;
    CHECK(vaporhook_prepare(engine, first.mapping, reinterpret_cast<void *>(detour_one),
                            &first_trampoline) == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_prepare(engine, second.mapping, reinterpret_cast<void *>(detour_two),
                            &second_trampoline) == VAPORHOOK_SUCCESS);

    second.release();
    const vaporhook_status_t installed = vaporhook_install(engine);
    CHECK(installed != VAPORHOOK_SUCCESS);
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_PREPARED);
    CHECK(first.function(0) == 41);
    CHECK(std::memcmp(first.mapping, first.original.data(), first.original.size()) == 0);
    MapPermissions first_permissions{};
    CHECK(permissions_for(first.mapping, &first_permissions));
    CHECK(exact_rx(first_permissions));

    void *third_trampoline = nullptr;
    const vaporhook_status_t third_prepare =
        vaporhook_prepare(engine, third.mapping, reinterpret_cast<void *>(detour_one),
                          &third_trampoline);
    if (third_prepare != VAPORHOOK_SUCCESS) {
        report("prepare after failed install", engine, third_prepare);
    }
    CHECK(third_prepare == VAPORHOOK_SUCCESS);
    CHECK(third.function(0) == 43);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
}

void test_install_patch_failure_rolls_back_prior_hooks() {
    AnonymousFunction first{};
    AnonymousFunction second{};
    CHECK(make_function(61, false, &first));
    CHECK(make_function(62, false, &second));
    if (first.function == nullptr || second.function == nullptr) {
        return;
    }

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *first_trampoline = nullptr;
    void *second_trampoline = nullptr;
    CHECK(vaporhook_prepare(engine, first.mapping, reinterpret_cast<void *>(detour_one),
                            &first_trampoline) == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_prepare(engine, second.mapping, reinterpret_cast<void *>(detour_two),
                            &second_trampoline) == VAPORHOOK_SUCCESS);

    wrapped_mprotect_calls.store(0, std::memory_order_release);
    wrapped_mprotect_failure.store(3, std::memory_order_release);
    wrapped_mprotect_saw_rwx.store(false, std::memory_order_release);
    wrapped_mprotect_monitor.store(true, std::memory_order_release);
    const vaporhook_status_t installed = vaporhook_install(engine);
    wrapped_mprotect_monitor.store(false, std::memory_order_release);
    wrapped_mprotect_failure.store(0, std::memory_order_release);

    CHECK(installed == VAPORHOOK_ERROR_MEMORY_PROTECTION);
    CHECK(wrapped_mprotect_calls.load(std::memory_order_acquire) == 5);
    CHECK(!wrapped_mprotect_saw_rwx.load(std::memory_order_acquire));
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_PREPARED);
    CHECK(first.function(0) == 61);
    CHECK(second.function(0) == 62);
    CHECK(std::memcmp(first.mapping, first.original.data(), first.original.size()) == 0);
    CHECK(std::memcmp(second.mapping, second.original.data(), second.original.size()) == 0);
    MapPermissions first_permissions{};
    MapPermissions second_permissions{};
    CHECK(permissions_for(first.mapping, &first_permissions));
    CHECK(permissions_for(second.mapping, &second_permissions));
    CHECK(exact_rx(first_permissions));
    CHECK(exact_rx(second_permissions));
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
    (void)first_trampoline;
    (void)second_trampoline;
}

void test_install_rx_restore_failure_restores_current_hook() {
    AnonymousFunction function{};
    CHECK(make_function(63, false, &function));
    if (function.function == nullptr) {
        return;
    }

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *trampoline = nullptr;
    CHECK(vaporhook_prepare(engine, function.mapping, reinterpret_cast<void *>(detour_one),
                            &trampoline) == VAPORHOOK_SUCCESS);

    wrapped_mprotect_calls.store(0, std::memory_order_release);
    wrapped_mprotect_failure.store(2, std::memory_order_release);
    wrapped_mprotect_saw_rwx.store(false, std::memory_order_release);
    wrapped_mprotect_monitor.store(true, std::memory_order_release);
    const vaporhook_status_t installed = vaporhook_install(engine);
    wrapped_mprotect_monitor.store(false, std::memory_order_release);
    wrapped_mprotect_failure.store(0, std::memory_order_release);

    CHECK(installed == VAPORHOOK_ERROR_MEMORY_PROTECTION);
    CHECK(wrapped_mprotect_calls.load(std::memory_order_acquire) == 4);
    CHECK(!wrapped_mprotect_saw_rwx.load(std::memory_order_acquire));
    CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_PREPARED);
    CHECK(function.function(0) == 63);
    CHECK(std::memcmp(function.mapping, function.original.data(), function.original.size()) == 0);
    MapPermissions permissions{};
    CHECK(permissions_for(function.mapping, &permissions));
    CHECK(exact_rx(permissions));
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
    (void)trampoline;
}

[[noreturn]] void inconsistent_uninstall_child() {
    int child_failures = 0;
#define CHILD_CHECK(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            ++child_failures;                                                                      \
        }                                                                                          \
    } while (false)

    AnonymousFunction first{};
    AnonymousFunction second{};
    CHILD_CHECK(make_function(51, false, &first));
    CHILD_CHECK(make_function(52, false, &second));
    vaporhook_engine_t *engine = nullptr;
    CHILD_CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *first_trampoline = nullptr;
    void *second_trampoline = nullptr;
    CHILD_CHECK(vaporhook_prepare(engine, first.mapping, reinterpret_cast<void *>(detour_one),
                                  &first_trampoline) == VAPORHOOK_SUCCESS);
    CHILD_CHECK(vaporhook_prepare(engine, second.mapping, reinterpret_cast<void *>(detour_two),
                                  &second_trampoline) == VAPORHOOK_SUCCESS);
    CHILD_CHECK(vaporhook_install(engine) == VAPORHOOK_SUCCESS);
    CHILD_CHECK(first.function(0) == 1001);
    CHILD_CHECK(second.function(0) == 1002);

    first.release();
    const vaporhook_status_t status = vaporhook_uninstall(engine);
    CHILD_CHECK(status != VAPORHOOK_SUCCESS);
    CHILD_CHECK(vaporhook_state(engine) == VAPORHOOK_STATE_INCONSISTENT);
    const int second_result = second.function(0);
    CHILD_CHECK(second_result == 52 || second_result == 1002);
    MapPermissions trampoline_permissions{};
    CHILD_CHECK(permissions_for(second_trampoline, &trampoline_permissions));
    CHILD_CHECK(exact_rx(trampoline_permissions));
    CHILD_CHECK(vaporhook_destroy(engine) == VAPORHOOK_ERROR_INCONSISTENT);
    (void)first_trampoline;
    ::_exit(child_failures == 0 ? 0 : 1);

#undef CHILD_CHECK
}

void test_uninstall_failure_retains_trampolines() {
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child < 0) {
        return;
    }
    if (child == 0) {
        inconsistent_uninstall_child();
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

void test_rwx_target_rejected_at_install() {
    AnonymousFunction function{};
    CHECK(make_function(77, true, &function));
    if (function.function == nullptr) {
        return;
    }

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *trampoline = nullptr;
    const vaporhook_status_t prepared =
        vaporhook_prepare(engine, function.mapping, reinterpret_cast<void *>(detour_one), &trampoline);
    if (prepared != VAPORHOOK_SUCCESS) {
        report("prepare rwx", engine, prepared);
    }
    CHECK(prepared == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_install(engine) == VAPORHOOK_ERROR_TARGET_PERMISSIONS);
    CHECK(function.function(0) == 77);
    CHECK(std::memcmp(function.mapping, function.original.data(), function.original.size()) == 0);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
}

void test_process_duplicate_registry() {
    AnonymousFunction function{};
    CHECK(make_function(88, false, &function));
    if (function.function == nullptr) {
        return;
    }

    vaporhook_engine_t *first = nullptr;
    vaporhook_engine_t *second = nullptr;
    CHECK(vaporhook_create(&first) == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_create(&second) == VAPORHOOK_SUCCESS);
    std::atomic<bool> start{false};
    vaporhook_status_t first_status = VAPORHOOK_ERROR_INVALID_STATE;
    vaporhook_status_t second_status = VAPORHOOK_ERROR_INVALID_STATE;
    void *first_trampoline = nullptr;
    void *second_trampoline = nullptr;

    auto prepare = [&](vaporhook_engine_t *engine, vaporhook_status_t *status,
                       void **trampoline) {
        while (!start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        *status = vaporhook_prepare(engine, function.mapping, reinterpret_cast<void *>(detour_one),
                                    trampoline);
    };
    std::thread first_thread(prepare, first, &first_status, &first_trampoline);
    std::thread second_thread(prepare, second, &second_status, &second_trampoline);
    start.store(true, std::memory_order_release);
    first_thread.join();
    second_thread.join();

    CHECK((first_status == VAPORHOOK_SUCCESS) != (second_status == VAPORHOOK_SUCCESS));
    CHECK(first_status == VAPORHOOK_SUCCESS || first_status == VAPORHOOK_ERROR_DUPLICATE_TARGET);
    CHECK(second_status == VAPORHOOK_SUCCESS || second_status == VAPORHOOK_ERROR_DUPLICATE_TARGET);
    CHECK(vaporhook_destroy(first) == VAPORHOOK_SUCCESS);
    CHECK(vaporhook_destroy(second) == VAPORHOOK_SUCCESS);
}

void test_relative_branch_relocation() {
    std::array<std::uint8_t, 16> external_code{};
    external_code.fill(0x90);
    external_code[0] = 0xEB; // jmp target+7, outside the five-byte patch block
    external_code[1] = 0x05;
    external_code[2] = 0xB8;
    const std::uint32_t unused = 17;
    std::memcpy(external_code.data() + 3, &unused, sizeof(unused));
    external_code[7] = 0xB8;
    const std::uint32_t answer = 42;
    std::memcpy(external_code.data() + 8, &answer, sizeof(answer));
    external_code[12] = 0xC3;

    std::array<std::uint8_t, 16> internal_code{};
    internal_code.fill(0x90);
    internal_code[0] = 0xEB; // jmp target+4, an instruction inside the relocated block
    internal_code[1] = 0x02;
    internal_code[4] = 0xB8;
    std::memcpy(internal_code.data() + 5, &answer, sizeof(answer));
    internal_code[9] = 0xC3;

    AnonymousFunction external{};
    AnonymousFunction internal{};
    CHECK(make_code_function(external_code, &external));
    CHECK(make_code_function(internal_code, &internal));
    if (external.function == nullptr || internal.function == nullptr) {
        return;
    }
    CHECK(external.function(0) == 42);
    CHECK(internal.function(0) == 42);

    vaporhook_engine_t *engine = nullptr;
    CHECK(vaporhook_create(&engine) == VAPORHOOK_SUCCESS);
    void *external_trampoline = nullptr;
    void *internal_trampoline = nullptr;
    const vaporhook_status_t external_prepare =
        vaporhook_prepare(engine, external.mapping, reinterpret_cast<void *>(detour_one),
                          &external_trampoline);
    if (external_prepare != VAPORHOOK_SUCCESS) {
        report("prepare external branch", engine, external_prepare);
    }
    CHECK(external_prepare == VAPORHOOK_SUCCESS);
    const vaporhook_status_t internal_prepare =
        vaporhook_prepare(engine, internal.mapping, reinterpret_cast<void *>(detour_two),
                          &internal_trampoline);
    if (internal_prepare != VAPORHOOK_SUCCESS) {
        report("prepare internal branch", engine, internal_prepare);
    }
    CHECK(internal_prepare == VAPORHOOK_SUCCESS);
    if (external_prepare != VAPORHOOK_SUCCESS || internal_prepare != VAPORHOOK_SUCCESS) {
        CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
        return;
    }

    CHECK(reinterpret_cast<HookFunction>(external_trampoline)(0) == 42);
    CHECK(reinterpret_cast<HookFunction>(internal_trampoline)(0) == 42);
    CHECK(vaporhook_install(engine) == VAPORHOOK_SUCCESS);
    CHECK(external.function(0) == 1001);
    CHECK(internal.function(0) == 1002);
    CHECK(reinterpret_cast<HookFunction>(external_trampoline)(0) == 42);
    CHECK(reinterpret_cast<HookFunction>(internal_trampoline)(0) == 42);
    CHECK(vaporhook_uninstall(engine) == VAPORHOOK_SUCCESS);
    CHECK(external.function(0) == 42);
    CHECK(internal.function(0) == 42);
    CHECK(vaporhook_destroy(engine) == VAPORHOOK_SUCCESS);
}

} // namespace

int main() {
    test_api_validation();
    test_fixture_lifecycle();
    test_install_preflight_failure_is_clean();
    test_install_patch_failure_rolls_back_prior_hooks();
    test_install_rx_restore_failure_restores_current_hook();
    test_uninstall_failure_retains_trampolines();
    test_rwx_target_rejected_at_install();
    test_process_duplicate_registry();
    test_relative_branch_relocation();

    if (failures == 0) {
        std::cout << "VaporHook tests passed\n";
        return 0;
    }
    std::cerr << failures << " VaporHook test(s) failed\n";
    return 1;
}
