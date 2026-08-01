#include "vaporhook/vaporhook.h"

#include <Zydis.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace {

constexpr std::size_t kMinimumPatchSize = 5;
constexpr std::size_t kMaximumOverwriteSize = 64;
constexpr std::size_t kRelaySize = 14;
constexpr std::size_t kErrorMessageSize = 256;

enum class EngineState : std::uint8_t {
    Empty,
    Prepared,
    Installed,
    Inconsistent,
};

struct MemoryMap {
    std::uintptr_t start{0};
    std::uintptr_t end{0};
    int prot{PROT_NONE};
};

enum class SpecialRelocation : std::uint8_t {
    None,
    MoveOriginalPc,
    Skip,
};

struct DecodedRecord {
    std::uintptr_t original_address{0};
    std::size_t original_offset{0};
    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    SpecialRelocation special{SpecialRelocation::None};
    ZydisRegister pc_register{ZYDIS_REGISTER_NONE};
    std::uint32_t original_pc{0};
};

struct HookEntry {
    void *target{nullptr};
    void *detour{nullptr};
    void *mapping{nullptr};
    std::size_t mapping_size{0};
    void *trampoline{nullptr};
    std::size_t patch_size{0};
    std::vector<std::uint8_t> original_bytes;
    std::vector<std::uint8_t> patch_bytes;

    HookEntry() = default;
    HookEntry(const HookEntry &) = delete;
    HookEntry &operator=(const HookEntry &) = delete;

    ~HookEntry() {
        if (mapping != nullptr && mapping_size != 0) {
            ::munmap(mapping, mapping_size);
        }
    }
};

struct ProcessRegistry {
    std::mutex mutex;
    std::unordered_map<std::uintptr_t, std::size_t> target_ranges;
};

ProcessRegistry &process_registry() {
    static ProcessRegistry *registry = new ProcessRegistry();
    return *registry;
}

std::size_t system_page_size() {
    static const std::size_t size = [] {
        const long value = ::sysconf(_SC_PAGESIZE);
        return value > 0 ? static_cast<std::size_t>(value) : std::size_t{4096};
    }();
    return size;
}

std::uintptr_t align_down(std::uintptr_t value, std::size_t alignment) {
    return value & ~(static_cast<std::uintptr_t>(alignment) - 1U);
}

std::optional<std::uintptr_t> align_up(std::uintptr_t value, std::size_t alignment) {
    const std::uintptr_t mask = static_cast<std::uintptr_t>(alignment) - 1U;
    if (value > std::numeric_limits<std::uintptr_t>::max() - mask) {
        return std::nullopt;
    }
    return (value + mask) & ~mask;
}

bool ranges_overlap(std::uintptr_t first_start, std::size_t first_size,
                    std::uintptr_t second_start, std::size_t second_size) {
    if (first_size == 0 || second_size == 0) {
        return false;
    }
    if (first_start > std::numeric_limits<std::uintptr_t>::max() - first_size ||
        second_start > std::numeric_limits<std::uintptr_t>::max() - second_size) {
        return true;
    }
    return first_start < second_start + second_size && second_start < first_start + first_size;
}

std::optional<std::uintptr_t> checked_address_add(std::uintptr_t address, std::size_t size) {
    if (address > std::numeric_limits<std::uintptr_t>::max() - size) {
        return std::nullopt;
    }
    return address + size;
}

bool displacement_fits_rel32(std::uintptr_t from_after, std::uintptr_t to) {
    if constexpr (sizeof(void *) == 4) {
        return true;
    }
    if (to >= from_after) {
        return to - from_after <= static_cast<std::uintptr_t>(INT32_MAX);
    }
    return from_after - to <= static_cast<std::uintptr_t>(INT32_MAX) + 1U;
}

bool write_relative_jump(std::uint8_t *output, std::uintptr_t instruction_address,
                         std::uintptr_t target) {
    const std::uintptr_t from_after = instruction_address + kMinimumPatchSize;
    if (!displacement_fits_rel32(from_after, target)) {
        return false;
    }
    output[0] = 0xE9;
    const std::uint32_t displacement = static_cast<std::uint32_t>(target - from_after);
    std::memcpy(output + 1, &displacement, sizeof(displacement));
    return true;
}

void write_absolute_jump64(std::uint8_t *output, std::uintptr_t target) {
    output[0] = 0xFF;
    output[1] = 0x25;
    output[2] = 0;
    output[3] = 0;
    output[4] = 0;
    output[5] = 0;
    const std::uint64_t address = static_cast<std::uint64_t>(target);
    std::memcpy(output + 6, &address, sizeof(address));
}

bool read_process_maps(std::vector<MemoryMap> &maps) {
    FILE *file = std::fopen("/proc/self/maps", "r");
    if (file == nullptr) {
        return false;
    }

    std::array<char, 4096> line{};
    while (std::fgets(line.data(), static_cast<int>(line.size()), file) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        std::array<char, 5> permissions{};
        if (std::sscanf(line.data(), "%llx-%llx %4s", &start, &end, permissions.data()) != 3 ||
            start >= end) {
            std::fclose(file);
            return false;
        }
        int prot = PROT_NONE;
        if (permissions[0] == 'r') {
            prot |= PROT_READ;
        }
        if (permissions[1] == 'w') {
            prot |= PROT_WRITE;
        }
        if (permissions[2] == 'x') {
            prot |= PROT_EXEC;
        }
        maps.push_back({static_cast<std::uintptr_t>(start), static_cast<std::uintptr_t>(end), prot});
    }
    const bool ok = std::ferror(file) == 0;
    std::fclose(file);
    return ok;
}

const MemoryMap *find_mapping(const std::vector<MemoryMap> &maps, std::uintptr_t address) {
    const auto iterator = std::lower_bound(
        maps.begin(), maps.end(), address,
        [](const MemoryMap &mapping, std::uintptr_t value) { return mapping.end <= value; });
    if (iterator == maps.end() || address < iterator->start || address >= iterator->end) {
        return nullptr;
    }
    return &*iterator;
}

bool query_pages(std::uintptr_t address, std::size_t size, bool require_strict_rx,
                 std::vector<std::uintptr_t> &pages) {
    if (size == 0 || address > std::numeric_limits<std::uintptr_t>::max() - size) {
        return false;
    }
    std::vector<MemoryMap> maps;
    if (!read_process_maps(maps)) {
        return false;
    }

    const std::size_t page_size = system_page_size();
    const std::uintptr_t first = align_down(address, page_size);
    const auto aligned_end = align_up(address + size, page_size);
    if (!aligned_end.has_value() || *aligned_end <= first) {
        return false;
    }

    for (std::uintptr_t page = first; page < *aligned_end; page += page_size) {
        const MemoryMap *mapping = find_mapping(maps, page);
        if (mapping == nullptr || mapping->end - page < page_size) {
            return false;
        }
        if (require_strict_rx) {
            if (mapping->prot != (PROT_READ | PROT_EXEC)) {
                return false;
            }
        } else if ((mapping->prot & (PROT_READ | PROT_EXEC)) !=
                   (PROT_READ | PROT_EXEC)) {
            return false;
        }
        pages.push_back(page);
    }
    return true;
}

bool readable_bytes_available(std::uintptr_t address, std::size_t *available_out) {
    std::vector<MemoryMap> maps;
    if (!read_process_maps(maps)) {
        return false;
    }
    const MemoryMap *mapping = find_mapping(maps, address);
    if (mapping == nullptr || (mapping->prot & (PROT_READ | PROT_EXEC)) !=
                                  (PROT_READ | PROT_EXEC)) {
        return false;
    }
    *available_out = mapping->end - address;
    return true;
}

std::uintptr_t address_distance(std::uintptr_t first, std::uintptr_t second) {
    return first >= second ? first - second : second - first;
}

void *allocate_trampoline_mapping(std::uintptr_t target, std::size_t size) {
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if constexpr (sizeof(void *) == 4) {
        void *mapping = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        return mapping == MAP_FAILED ? nullptr : mapping;
    }

    std::vector<MemoryMap> maps;
    if (!read_process_maps(maps)) {
        return nullptr;
    }

    const std::size_t page_size = system_page_size();
    const std::uintptr_t reach = static_cast<std::uintptr_t>(INT32_MAX);
    const std::uintptr_t low = target > reach ? target - reach : page_size;
    const std::uintptr_t high =
        target < std::numeric_limits<std::uintptr_t>::max() - reach
            ? target + reach
            : std::numeric_limits<std::uintptr_t>::max() - size;

    std::vector<std::uintptr_t> candidates;
    std::uintptr_t cursor = align_up(low, page_size).value_or(low);
    for (const MemoryMap &mapping : maps) {
        if (mapping.end <= cursor) {
            continue;
        }
        if (mapping.start >= high) {
            break;
        }
        if (mapping.start > cursor && mapping.start - cursor >= size) {
            const std::uintptr_t gap_end = std::min(mapping.start, high);
            std::uintptr_t candidate = cursor;
            if (target >= cursor && target < gap_end) {
                candidate = align_down(target, page_size);
                if (candidate + size > gap_end) {
                    candidate = align_down(gap_end - size, page_size);
                }
            } else if (target >= gap_end) {
                candidate = align_down(gap_end - size, page_size);
            }
            if (candidate >= cursor && candidate <= gap_end - size) {
                candidates.push_back(candidate);
            }
        }
        cursor = std::max(cursor, mapping.end);
        const auto aligned = align_up(cursor, page_size);
        if (!aligned.has_value()) {
            break;
        }
        cursor = *aligned;
    }
    if (cursor < high && high - cursor >= size) {
        candidates.push_back(target >= cursor ? align_down(std::min(target, high - size), page_size)
                                              : cursor);
    }

    std::sort(candidates.begin(), candidates.end(), [target](std::uintptr_t first,
                                                             std::uintptr_t second) {
        return address_distance(first, target) < address_distance(second, target);
    });
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

    for (const std::uintptr_t candidate : candidates) {
        void *requested = reinterpret_cast<void *>(candidate);
        void *mapping = ::mmap(requested, size, PROT_READ | PROT_WRITE,
                               flags | MAP_FIXED_NOREPLACE, -1, 0);
        if (mapping == MAP_FAILED) {
            continue;
        }
        if (mapping != requested) {
            ::munmap(mapping, size);
            continue;
        }
        const std::uintptr_t relay = candidate + size - kRelaySize;
        if (displacement_fits_rel32(target + kMinimumPatchSize, relay)) {
            return mapping;
        }
        ::munmap(mapping, size);
    }
    return nullptr;
}

std::optional<std::uintptr_t> relative_target(const DecodedRecord &record) {
    for (std::uint8_t index = 0; index < record.instruction.operand_count_visible; ++index) {
        const ZydisDecodedOperand &operand = record.operands[index];
        if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operand.imm.is_relative) {
            continue;
        }
        ZyanU64 result = 0;
        if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&record.instruction, &operand,
                                                record.original_address, &result))) {
            return std::nullopt;
        }
        return static_cast<std::uintptr_t>(result);
    }
    return std::nullopt;
}

std::optional<std::uint8_t> mov_immediate_opcode(ZydisRegister reg) {
    switch (reg) {
    case ZYDIS_REGISTER_EAX:
        return 0xB8;
    case ZYDIS_REGISTER_ECX:
        return 0xB9;
    case ZYDIS_REGISTER_EDX:
        return 0xBA;
    case ZYDIS_REGISTER_EBX:
        return 0xBB;
    case ZYDIS_REGISTER_ESP:
        return 0xBC;
    case ZYDIS_REGISTER_EBP:
        return 0xBD;
    case ZYDIS_REGISTER_ESI:
        return 0xBE;
    case ZYDIS_REGISTER_EDI:
        return 0xBF;
    default:
        return std::nullopt;
    }
}

std::optional<ZydisRegister> get_pc_thunk_register(std::uintptr_t target) {
    std::size_t available = 0;
    if (!readable_bytes_available(target, &available) || available < 4) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 4> bytes{};
    std::memcpy(bytes.data(), reinterpret_cast<const void *>(target), bytes.size());
    if (bytes[0] != 0x8B || bytes[2] != 0x24 || bytes[3] != 0xC3) {
        return std::nullopt;
    }
    switch (bytes[1]) {
    case 0x04:
        return ZYDIS_REGISTER_EAX;
    case 0x0C:
        return ZYDIS_REGISTER_ECX;
    case 0x14:
        return ZYDIS_REGISTER_EDX;
    case 0x1C:
        return ZYDIS_REGISTER_EBX;
    case 0x2C:
        return ZYDIS_REGISTER_EBP;
    case 0x34:
        return ZYDIS_REGISTER_ESI;
    case 0x3C:
        return ZYDIS_REGISTER_EDI;
    default:
        return std::nullopt;
    }
}

vaporhook_status_t decode_target(std::uintptr_t target, std::vector<DecodedRecord> &records,
                                 std::size_t &patch_size) {
    std::size_t available = 0;
    if (!readable_bytes_available(target, &available)) {
        return VAPORHOOK_ERROR_TARGET_MAPPING;
    }
    available = std::min(available, kMaximumOverwriteSize + ZYDIS_MAX_INSTRUCTION_LENGTH);

    ZydisDecoder decoder{};
    const ZydisMachineMode mode =
        sizeof(void *) == 8 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    const ZydisStackWidth width =
        sizeof(void *) == 8 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, mode, width))) {
        return VAPORHOOK_ERROR_DECODE;
    }

    patch_size = 0;
    while (patch_size < kMinimumPatchSize) {
        if (patch_size >= available || patch_size > kMaximumOverwriteSize) {
            return VAPORHOOK_ERROR_DECODE;
        }
        DecodedRecord record{};
        record.original_address = target + patch_size;
        record.original_offset = patch_size;
        const ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, reinterpret_cast<const void *>(record.original_address), available - patch_size,
            &record.instruction, record.operands.data());
        if (ZYAN_FAILED(status) || record.instruction.length == 0) {
            return VAPORHOOK_ERROR_DECODE;
        }
        patch_size += record.instruction.length;
        if (patch_size > kMaximumOverwriteSize) {
            return VAPORHOOK_ERROR_DECODE;
        }
        records.push_back(record);
    }

    if constexpr (sizeof(void *) == 4) {
        DecodedRecord &last = records.back();
        const auto call_target = relative_target(last);
        if (last.instruction.mnemonic == ZYDIS_MNEMONIC_CALL && call_target.has_value() &&
            *call_target == last.original_address + last.instruction.length) {
            if (patch_size >= available) {
                return VAPORHOOK_ERROR_DECODE;
            }
            DecodedRecord pop{};
            pop.original_address = target + patch_size;
            pop.original_offset = patch_size;
            const ZyanStatus status = ZydisDecoderDecodeFull(
                &decoder, reinterpret_cast<const void *>(pop.original_address), available - patch_size,
                &pop.instruction, pop.operands.data());
            if (ZYAN_FAILED(status) || pop.instruction.length == 0) {
                return VAPORHOOK_ERROR_DECODE;
            }
            patch_size += pop.instruction.length;
            records.push_back(pop);
        }

        for (std::size_t index = 0; index < records.size(); ++index) {
            DecodedRecord &record = records[index];
            if (record.instruction.mnemonic != ZYDIS_MNEMONIC_CALL) {
                continue;
            }
            const auto call_target = relative_target(record);
            if (!call_target.has_value()) {
                continue;
            }
            if (*call_target == record.original_address + record.instruction.length &&
                index + 1 < records.size()) {
                DecodedRecord &pop = records[index + 1];
                if (pop.instruction.mnemonic == ZYDIS_MNEMONIC_POP &&
                    pop.instruction.operand_count_visible == 1 &&
                    pop.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    mov_immediate_opcode(pop.operands[0].reg.value).has_value()) {
                    record.special = SpecialRelocation::MoveOriginalPc;
                    record.pc_register = pop.operands[0].reg.value;
                    record.original_pc = static_cast<std::uint32_t>(
                        record.original_address + record.instruction.length);
                    pop.special = SpecialRelocation::Skip;
                    continue;
                }
            }
            const auto thunk_reg = get_pc_thunk_register(*call_target);
            if (thunk_reg.has_value()) {
                record.special = SpecialRelocation::MoveOriginalPc;
                record.pc_register = *thunk_reg;
                record.original_pc = static_cast<std::uint32_t>(
                    record.original_address + record.instruction.length);
            }
        }
    }

    return VAPORHOOK_SUCCESS;
}

std::optional<std::size_t> internal_target_index(const std::vector<DecodedRecord> &records,
                                                 std::uintptr_t block_start,
                                                 std::size_t block_size,
                                                 std::uintptr_t address) {
    const auto block_end = checked_address_add(block_start, block_size);
    if (!block_end.has_value() || address < block_start || address >= *block_end) {
        return std::nullopt;
    }
    for (std::size_t index = 0; index < records.size(); ++index) {
        if (records[index].original_address == address) {
            return index;
        }
    }
    return records.size();
}

vaporhook_status_t encode_record(const DecodedRecord &record,
                                 const std::vector<DecodedRecord> &records,
                                 const std::vector<std::size_t> &offsets,
                                 std::uintptr_t block_start, std::size_t block_size,
                                 std::uintptr_t trampoline_start, std::uint8_t *output,
                                 std::size_t *length_out) {
    if (record.special == SpecialRelocation::Skip) {
        *length_out = 0;
        return VAPORHOOK_SUCCESS;
    }
    if (record.special == SpecialRelocation::MoveOriginalPc) {
        const auto opcode = mov_immediate_opcode(record.pc_register);
        if (!opcode.has_value()) {
            return VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION;
        }
        if (output != nullptr) {
            output[0] = *opcode;
            std::memcpy(output + 1, &record.original_pc, sizeof(record.original_pc));
        }
        *length_out = 5;
        return VAPORHOOK_SUCCESS;
    }

    bool requires_reencoding = false;
    for (std::uint8_t index = 0; index < record.instruction.operand_count_visible; ++index) {
        const ZydisDecodedOperand &operand = record.operands[index];
        if ((operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) ||
            (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
             (operand.mem.base == ZYDIS_REGISTER_EIP || operand.mem.base == ZYDIS_REGISTER_RIP))) {
            requires_reencoding = true;
            break;
        }
    }
    if (!requires_reencoding) {
        if (output != nullptr) {
            std::memcpy(output, reinterpret_cast<const void *>(record.original_address),
                        record.instruction.length);
        }
        *length_out = record.instruction.length;
        return VAPORHOOK_SUCCESS;
    }

    if (record.instruction.mnemonic == ZYDIS_MNEMONIC_XBEGIN) {
        return VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION;
    }

    ZydisEncoderRequest request{};
    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
            &record.instruction, record.operands.data(), record.instruction.operand_count_visible,
            &request))) {
        return VAPORHOOK_ERROR_RELOCATION;
    }

    for (std::uint8_t index = 0; index < record.instruction.operand_count_visible; ++index) {
        const ZydisDecodedOperand &operand = record.operands[index];
        ZyanU64 absolute = 0;
        if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
            if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&record.instruction, &operand,
                                                    record.original_address, &absolute))) {
                return VAPORHOOK_ERROR_RELOCATION;
            }
            const auto internal = internal_target_index(records, block_start, block_size,
                                                        static_cast<std::uintptr_t>(absolute));
            if (internal.has_value()) {
                if (*internal >= records.size() || records[*internal].special == SpecialRelocation::Skip) {
                    return VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION;
                }
                absolute = trampoline_start + offsets[*internal];
            }
            request.operands[index].imm.u = absolute;
            request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
            request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
        } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   (operand.mem.base == ZYDIS_REGISTER_EIP ||
                    operand.mem.base == ZYDIS_REGISTER_RIP)) {
            if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&record.instruction, &operand,
                                                    record.original_address, &absolute))) {
                return VAPORHOOK_ERROR_RELOCATION;
            }
            const auto block_end = checked_address_add(block_start, block_size);
            if (!block_end.has_value()) {
                return VAPORHOOK_ERROR_RELOCATION;
            }
            if (absolute >= block_start && absolute < *block_end) {
                return VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION;
            }
            request.operands[index].mem.displacement = static_cast<ZyanI64>(absolute);
        }
    }

    std::array<std::uint8_t, 32> encoded{};
    ZyanUSize encoded_length = encoded.size();
    const std::uintptr_t runtime_address = trampoline_start + offsets[&record - records.data()];
    if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(&request, encoded.data(),
                                                          &encoded_length, runtime_address))) {
        return VAPORHOOK_ERROR_RELOCATION;
    }
    if (output != nullptr) {
        std::memcpy(output, encoded.data(), encoded_length);
    }
    *length_out = encoded_length;
    return VAPORHOOK_SUCCESS;
}

vaporhook_status_t relocate_block(const std::vector<DecodedRecord> &records,
                                  std::uintptr_t block_start, std::size_t block_size,
                                  std::uint8_t *trampoline, std::size_t capacity,
                                  std::size_t *relocated_size_out) {
    std::vector<std::size_t> lengths;
    lengths.reserve(records.size());
    for (const DecodedRecord &record : records) {
        if (record.special == SpecialRelocation::Skip) {
            lengths.push_back(0);
        } else if (record.special == SpecialRelocation::MoveOriginalPc) {
            lengths.push_back(5);
        } else {
            lengths.push_back(record.instruction.length);
        }
    }

    std::vector<std::size_t> offsets(records.size());
    bool stable = false;
    for (int iteration = 0; iteration < 8; ++iteration) {
        std::size_t offset = 0;
        for (std::size_t index = 0; index < records.size(); ++index) {
            offsets[index] = offset;
            offset += lengths[index];
        }

        std::vector<std::size_t> updated(records.size());
        for (std::size_t index = 0; index < records.size(); ++index) {
            const vaporhook_status_t status =
                encode_record(records[index], records, offsets, block_start, block_size,
                              reinterpret_cast<std::uintptr_t>(trampoline), nullptr, &updated[index]);
            if (status != VAPORHOOK_SUCCESS) {
                return status;
            }
        }
        if (updated == lengths) {
            stable = true;
            break;
        }
        lengths = std::move(updated);
    }
    if (!stable) {
        return VAPORHOOK_ERROR_RELOCATION;
    }

    std::size_t total = 0;
    for (std::size_t index = 0; index < records.size(); ++index) {
        offsets[index] = total;
        total += lengths[index];
    }
    if (total > capacity) {
        return VAPORHOOK_ERROR_RELOCATION;
    }

    for (std::size_t index = 0; index < records.size(); ++index) {
        std::size_t encoded_length = 0;
        const vaporhook_status_t status =
            encode_record(records[index], records, offsets, block_start, block_size,
                          reinterpret_cast<std::uintptr_t>(trampoline), trampoline + offsets[index],
                          &encoded_length);
        if (status != VAPORHOOK_SUCCESS || encoded_length != lengths[index]) {
            return status == VAPORHOOK_SUCCESS ? VAPORHOOK_ERROR_RELOCATION : status;
        }
    }
    *relocated_size_out = total;
    return VAPORHOOK_SUCCESS;
}

struct MappingGuard {
    void *address{nullptr};
    std::size_t size{0};

    ~MappingGuard() {
        if (address != nullptr) {
            ::munmap(address, size);
        }
    }

    void release() {
        address = nullptr;
        size = 0;
    }
};

} // namespace

struct vaporhook_engine {
    mutable std::mutex mutex;
    EngineState state{EngineState::Empty};
    std::vector<std::unique_ptr<HookEntry>> entries;
    std::array<char, kErrorMessageSize> error{};
};

namespace {

vaporhook_status_t set_error(vaporhook_engine &engine, vaporhook_status_t status,
                             const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(engine.error.data(), engine.error.size(), format, arguments);
    va_end(arguments);
    return status;
}

void clear_error(vaporhook_engine &engine) {
    engine.error[0] = '\0';
}

vaporhook_status_t prepare_entry(vaporhook_engine &engine, void *target_ptr, void *detour_ptr,
                                 std::unique_ptr<HookEntry> &entry_out) {
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(target_ptr);
    const std::uintptr_t detour = reinterpret_cast<std::uintptr_t>(detour_ptr);

    std::vector<DecodedRecord> records;
    std::size_t patch_size = 0;
    vaporhook_status_t status = decode_target(target, records, patch_size);
    if (status != VAPORHOOK_SUCCESS) {
        return set_error(engine, status, "failed to decode target %p", target_ptr);
    }

    const std::size_t mapping_size = system_page_size();
    void *mapping = allocate_trampoline_mapping(target, mapping_size);
    if (mapping == nullptr) {
        return set_error(engine, VAPORHOOK_ERROR_NO_MEMORY,
                         "could not allocate a trampoline within rel32 reach of %p", target_ptr);
    }
    MappingGuard mapping_guard{mapping, mapping_size};
    auto *trampoline = static_cast<std::uint8_t *>(mapping);
    const std::size_t relay_offset = mapping_size - kRelaySize;

    std::size_t relocated_size = 0;
    status = relocate_block(records, target, patch_size, trampoline,
                            relay_offset - kMinimumPatchSize, &relocated_size);
    if (status != VAPORHOOK_SUCCESS) {
        return set_error(engine, status, "failed to relocate target %p", target_ptr);
    }

    if (!write_relative_jump(trampoline + relocated_size,
                             reinterpret_cast<std::uintptr_t>(trampoline) + relocated_size,
                             target + patch_size)) {
        return set_error(engine, VAPORHOOK_ERROR_RELOCATION,
                         "trampoline jump-back for %p is outside rel32 range", target_ptr);
    }

    std::uintptr_t patch_destination = detour;
    if constexpr (sizeof(void *) == 8) {
        auto *relay = trampoline + relay_offset;
        write_absolute_jump64(relay, detour);
        patch_destination = reinterpret_cast<std::uintptr_t>(relay);
    }

    std::unique_ptr<HookEntry> entry = std::make_unique<HookEntry>();
    entry->target = target_ptr;
    entry->detour = detour_ptr;
    entry->trampoline = mapping;
    entry->patch_size = patch_size;
    entry->original_bytes.resize(patch_size);
    entry->patch_bytes.assign(patch_size, 0x90);
    std::memcpy(entry->original_bytes.data(), target_ptr, patch_size);
    if (!write_relative_jump(entry->patch_bytes.data(), target, patch_destination)) {
        return set_error(engine, VAPORHOOK_ERROR_RELOCATION,
                         "target jump for %p is outside rel32 range", target_ptr);
    }

    __builtin___clear_cache(reinterpret_cast<char *>(mapping),
                            reinterpret_cast<char *>(mapping) + mapping_size);
    if (::mprotect(mapping, mapping_size, PROT_READ | PROT_EXEC) != 0) {
        return set_error(engine, VAPORHOOK_ERROR_MEMORY_PROTECTION,
                         "could not mark trampoline executable: %s", std::strerror(errno));
    }

    entry->mapping = mapping;
    entry->mapping_size = mapping_size;
    mapping_guard.release();
    entry_out = std::move(entry);
    return VAPORHOOK_SUCCESS;
}

vaporhook_status_t restore_pages_rx(const std::vector<std::uintptr_t> &pages) {
    const std::size_t page_size = system_page_size();
    vaporhook_status_t status = VAPORHOOK_SUCCESS;
    for (const std::uintptr_t page : pages) {
        if (::mprotect(reinterpret_cast<void *>(page), page_size, PROT_READ | PROT_EXEC) != 0) {
            status = VAPORHOOK_ERROR_MEMORY_PROTECTION;
        }
    }
    return status;
}

vaporhook_status_t apply_entry_bytes(HookEntry &entry, const std::vector<std::uint8_t> &desired,
                                     const std::vector<std::uint8_t> &previous,
                                     bool *inconsistent_out) {
    std::vector<std::uintptr_t> pages;
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(entry.target);
    if (!query_pages(target, entry.patch_size, true, pages)) {
        return VAPORHOOK_ERROR_TARGET_PERMISSIONS;
    }

    const std::size_t page_size = system_page_size();
    std::size_t writable_count = 0;
    for (; writable_count < pages.size(); ++writable_count) {
        if (::mprotect(reinterpret_cast<void *>(pages[writable_count]), page_size,
                       PROT_READ | PROT_WRITE) != 0) {
            std::vector<std::uintptr_t> opened(pages.begin(), pages.begin() + writable_count);
            if (restore_pages_rx(opened) != VAPORHOOK_SUCCESS) {
                *inconsistent_out = true;
                return VAPORHOOK_ERROR_ROLLBACK;
            }
            return VAPORHOOK_ERROR_MEMORY_PROTECTION;
        }
    }

    std::memcpy(entry.target, desired.data(), desired.size());
    __builtin___clear_cache(static_cast<char *>(entry.target),
                            static_cast<char *>(entry.target) + desired.size());
    if (restore_pages_rx(pages) == VAPORHOOK_SUCCESS) {
        return VAPORHOOK_SUCCESS;
    }

    bool reopened = true;
    for (const std::uintptr_t page : pages) {
        if (::mprotect(reinterpret_cast<void *>(page), page_size, PROT_READ | PROT_WRITE) != 0) {
            reopened = false;
            break;
        }
    }
    if (reopened) {
        std::memcpy(entry.target, previous.data(), previous.size());
        __builtin___clear_cache(static_cast<char *>(entry.target),
                                static_cast<char *>(entry.target) + previous.size());
    }
    if (!reopened || restore_pages_rx(pages) != VAPORHOOK_SUCCESS) {
        *inconsistent_out = true;
        return VAPORHOOK_ERROR_ROLLBACK;
    }
    return VAPORHOOK_ERROR_MEMORY_PROTECTION;
}

bool preflight_entry(const HookEntry &entry) {
    std::vector<std::uintptr_t> pages;
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(entry.target);
    return query_pages(target, entry.patch_size, true, pages) &&
           std::memcmp(entry.target, entry.original_bytes.data(), entry.patch_size) == 0;
}

vaporhook_state_t public_state(EngineState state) {
    switch (state) {
    case EngineState::Empty:
        return VAPORHOOK_STATE_EMPTY;
    case EngineState::Prepared:
        return VAPORHOOK_STATE_PREPARED;
    case EngineState::Installed:
        return VAPORHOOK_STATE_INSTALLED;
    case EngineState::Inconsistent:
        return VAPORHOOK_STATE_INCONSISTENT;
    }
    return VAPORHOOK_STATE_INCONSISTENT;
}

} // namespace

extern "C" vaporhook_status_t vaporhook_create(vaporhook_engine_t **engine_out) {
    if (engine_out == nullptr) {
        return VAPORHOOK_ERROR_INVALID_ARGUMENT;
    }
    *engine_out = new (std::nothrow) vaporhook_engine();
    return *engine_out != nullptr ? VAPORHOOK_SUCCESS : VAPORHOOK_ERROR_NO_MEMORY;
}

extern "C" vaporhook_status_t vaporhook_prepare(vaporhook_engine_t *engine, void *target,
                                                void *detour, void **trampoline_out) {
    if (engine == nullptr || target == nullptr || detour == nullptr || trampoline_out == nullptr ||
        target == detour) {
        return VAPORHOOK_ERROR_INVALID_ARGUMENT;
    }
    *trampoline_out = nullptr;

    try {
        std::lock_guard engine_lock(engine->mutex);
        if (engine->state == EngineState::Installed || engine->state == EngineState::Inconsistent) {
            return set_error(*engine, VAPORHOOK_ERROR_INVALID_STATE,
                             "prepare requires an empty or prepared engine");
        }
        if (engine->entries.size() >= VAPORHOOK_MAX_HOOKS) {
            return set_error(*engine, VAPORHOOK_ERROR_TOO_MANY_HOOKS,
                             "an engine supports at most %d hooks", VAPORHOOK_MAX_HOOKS);
        }
        for (const auto &entry : engine->entries) {
            if (entry->target == target) {
                return set_error(*engine, VAPORHOOK_ERROR_DUPLICATE_TARGET,
                                 "target %p is already prepared", target);
            }
        }
        engine->entries.reserve(engine->entries.size() + 1);

        std::unique_ptr<HookEntry> entry;
        const vaporhook_status_t prepared = prepare_entry(*engine, target, detour, entry);
        if (prepared != VAPORHOOK_SUCCESS) {
            return prepared;
        }

        const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(target);
        for (const auto &existing : engine->entries) {
            if (ranges_overlap(start, entry->patch_size,
                               reinterpret_cast<std::uintptr_t>(existing->target),
                               existing->patch_size)) {
                return set_error(*engine, VAPORHOOK_ERROR_OVERLAPPING_TARGET,
                                 "target range at %p overlaps an existing hook", target);
            }
        }

        ProcessRegistry &registry = process_registry();
        std::lock_guard registry_lock(registry.mutex);
        for (const auto &[registered_start, registered_size] : registry.target_ranges) {
            if (ranges_overlap(start, entry->patch_size, registered_start, registered_size)) {
                return set_error(*engine, VAPORHOOK_ERROR_DUPLICATE_TARGET,
                                 "target range at %p is owned by another engine", target);
            }
        }
        const auto [registration, inserted] =
            registry.target_ranges.emplace(start, entry->patch_size);
        if (!inserted) {
            return set_error(*engine, VAPORHOOK_ERROR_DUPLICATE_TARGET,
                             "target range at %p is already registered", target);
        }

        void *const trampoline = entry->trampoline;
        try {
            engine->entries.push_back(std::move(entry));
        } catch (...) {
            registry.target_ranges.erase(registration);
            throw;
        }
        *trampoline_out = trampoline;
        engine->state = EngineState::Prepared;
        clear_error(*engine);
        return VAPORHOOK_SUCCESS;
    } catch (const std::bad_alloc &) {
        return set_error(*engine, VAPORHOOK_ERROR_NO_MEMORY, "allocation failed during prepare");
    } catch (...) {
        return set_error(*engine, VAPORHOOK_ERROR_PATCH, "unexpected failure during prepare");
    }
}

extern "C" vaporhook_status_t vaporhook_install(vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return VAPORHOOK_ERROR_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard engine_lock(engine->mutex);
        if (engine->state != EngineState::Prepared || engine->entries.empty()) {
            return set_error(*engine, VAPORHOOK_ERROR_INVALID_STATE,
                             "install requires at least one prepared hook");
        }

        ProcessRegistry &registry = process_registry();
        std::lock_guard registry_lock(registry.mutex);
        for (const auto &entry : engine->entries) {
            if (!preflight_entry(*entry)) {
                return set_error(*engine, VAPORHOOK_ERROR_TARGET_PERMISSIONS,
                                 "target %p changed, disappeared, or is not strict r-x", entry->target);
            }
        }

        std::size_t installed = 0;
        for (; installed < engine->entries.size(); ++installed) {
            HookEntry &entry = *engine->entries[installed];
            bool inconsistent = false;
            const vaporhook_status_t status =
                apply_entry_bytes(entry, entry.patch_bytes, entry.original_bytes, &inconsistent);
            if (status == VAPORHOOK_SUCCESS) {
                continue;
            }

            bool rollback_failed = inconsistent;
            while (installed != 0) {
                --installed;
                HookEntry &prior = *engine->entries[installed];
                bool prior_inconsistent = false;
                const vaporhook_status_t rollback =
                    apply_entry_bytes(prior, prior.original_bytes, prior.patch_bytes,
                                      &prior_inconsistent);
                if (rollback != VAPORHOOK_SUCCESS || prior_inconsistent) {
                    rollback_failed = true;
                }
            }
            if (rollback_failed) {
                engine->state = EngineState::Inconsistent;
                return set_error(*engine, VAPORHOOK_ERROR_ROLLBACK,
                                 "install failed and rollback was incomplete");
            }
            return set_error(*engine, status, "install failed while patching target %p", entry.target);
        }

        engine->state = EngineState::Installed;
        clear_error(*engine);
        return VAPORHOOK_SUCCESS;
    } catch (const std::bad_alloc &) {
        return set_error(*engine, VAPORHOOK_ERROR_NO_MEMORY, "allocation failed during install");
    } catch (...) {
        return set_error(*engine, VAPORHOOK_ERROR_PATCH, "unexpected failure during install");
    }
}

extern "C" vaporhook_status_t vaporhook_uninstall(vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return VAPORHOOK_ERROR_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard engine_lock(engine->mutex);
        if (engine->state != EngineState::Installed) {
            return set_error(*engine, VAPORHOOK_ERROR_INVALID_STATE,
                             "uninstall requires an installed engine");
        }

        ProcessRegistry &registry = process_registry();
        std::lock_guard registry_lock(registry.mutex);
        vaporhook_status_t first_error = VAPORHOOK_SUCCESS;
        bool inconsistent = false;
        for (const auto &entry_ptr : engine->entries) {
            HookEntry &entry = *entry_ptr;
            bool entry_inconsistent = false;
            const vaporhook_status_t status =
                apply_entry_bytes(entry, entry.original_bytes, entry.patch_bytes,
                                  &entry_inconsistent);
            if (status != VAPORHOOK_SUCCESS && first_error == VAPORHOOK_SUCCESS) {
                first_error = status;
            }
            inconsistent = inconsistent || entry_inconsistent || status != VAPORHOOK_SUCCESS;
        }

        if (inconsistent) {
            engine->state = EngineState::Inconsistent;
            return set_error(*engine,
                             first_error == VAPORHOOK_SUCCESS ? VAPORHOOK_ERROR_INCONSISTENT
                                                              : first_error,
                             "one or more targets could not be restored; trampolines retained");
        }
        engine->state = EngineState::Prepared;
        clear_error(*engine);
        return VAPORHOOK_SUCCESS;
    } catch (const std::bad_alloc &) {
        std::lock_guard lock(engine->mutex);
        engine->state = EngineState::Inconsistent;
        return set_error(*engine, VAPORHOOK_ERROR_NO_MEMORY,
                         "allocation failed during uninstall; trampolines retained");
    } catch (...) {
        std::lock_guard lock(engine->mutex);
        engine->state = EngineState::Inconsistent;
        return set_error(*engine, VAPORHOOK_ERROR_PATCH,
                         "unexpected uninstall failure; trampolines retained");
    }
}

extern "C" vaporhook_status_t vaporhook_destroy(vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return VAPORHOOK_ERROR_INVALID_ARGUMENT;
    }

    std::unique_lock engine_lock(engine->mutex);
    if (engine->state == EngineState::Installed) {
        return set_error(*engine, VAPORHOOK_ERROR_INVALID_STATE,
                         "installed engines must be uninstalled before destroy");
    }
    if (engine->state == EngineState::Inconsistent) {
        return set_error(*engine, VAPORHOOK_ERROR_INCONSISTENT,
                         "inconsistent engine retained to keep trampolines alive");
    }

    ProcessRegistry &registry = process_registry();
    {
        std::lock_guard registry_lock(registry.mutex);
        for (const auto &entry : engine->entries) {
            registry.target_ranges.erase(reinterpret_cast<std::uintptr_t>(entry->target));
        }
    }
    engine_lock.unlock();
    delete engine;
    return VAPORHOOK_SUCCESS;
}

extern "C" vaporhook_state_t vaporhook_state(const vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return VAPORHOOK_STATE_INCONSISTENT;
    }
    std::lock_guard lock(engine->mutex);
    return public_state(engine->state);
}

extern "C" size_t vaporhook_hook_count(const vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return 0;
    }
    std::lock_guard lock(engine->mutex);
    return engine->entries.size();
}

extern "C" const char *vaporhook_error_message(const vaporhook_engine_t *engine) {
    if (engine == nullptr) {
        return "invalid engine";
    }
    std::lock_guard lock(engine->mutex);
    return engine->error.data();
}

extern "C" const char *vaporhook_status_string(vaporhook_status_t status) {
    switch (status) {
    case VAPORHOOK_SUCCESS:
        return "success";
    case VAPORHOOK_ERROR_INVALID_ARGUMENT:
        return "invalid argument";
    case VAPORHOOK_ERROR_INVALID_STATE:
        return "invalid state";
    case VAPORHOOK_ERROR_NO_MEMORY:
        return "out of memory";
    case VAPORHOOK_ERROR_TOO_MANY_HOOKS:
        return "too many hooks";
    case VAPORHOOK_ERROR_DUPLICATE_TARGET:
        return "duplicate target";
    case VAPORHOOK_ERROR_OVERLAPPING_TARGET:
        return "overlapping target";
    case VAPORHOOK_ERROR_TARGET_MAPPING:
        return "target mapping error";
    case VAPORHOOK_ERROR_TARGET_PERMISSIONS:
        return "target permissions error";
    case VAPORHOOK_ERROR_DECODE:
        return "decode error";
    case VAPORHOOK_ERROR_RELOCATION:
        return "relocation error";
    case VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION:
        return "unsupported instruction";
    case VAPORHOOK_ERROR_MEMORY_PROTECTION:
        return "memory protection error";
    case VAPORHOOK_ERROR_PATCH:
        return "patch error";
    case VAPORHOOK_ERROR_ROLLBACK:
        return "rollback error";
    case VAPORHOOK_ERROR_INCONSISTENT:
        return "inconsistent engine";
    }
    return "unknown status";
}
