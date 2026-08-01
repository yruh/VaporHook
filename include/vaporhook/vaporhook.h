#ifndef VAPORHOOK_VAPORHOOK_H
#define VAPORHOOK_VAPORHOOK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vaporhook_engine vaporhook_engine_t;

typedef enum vaporhook_status {
    VAPORHOOK_SUCCESS = 0,
    VAPORHOOK_ERROR_INVALID_ARGUMENT = 1,
    VAPORHOOK_ERROR_INVALID_STATE = 2,
    VAPORHOOK_ERROR_NO_MEMORY = 3,
    VAPORHOOK_ERROR_TOO_MANY_HOOKS = 4,
    VAPORHOOK_ERROR_DUPLICATE_TARGET = 5,
    VAPORHOOK_ERROR_OVERLAPPING_TARGET = 6,
    VAPORHOOK_ERROR_TARGET_MAPPING = 7,
    VAPORHOOK_ERROR_TARGET_PERMISSIONS = 8,
    VAPORHOOK_ERROR_DECODE = 9,
    VAPORHOOK_ERROR_RELOCATION = 10,
    VAPORHOOK_ERROR_UNSUPPORTED_INSTRUCTION = 11,
    VAPORHOOK_ERROR_MEMORY_PROTECTION = 12,
    VAPORHOOK_ERROR_PATCH = 13,
    VAPORHOOK_ERROR_ROLLBACK = 14,
    VAPORHOOK_ERROR_INCONSISTENT = 15,
} vaporhook_status_t;

typedef enum vaporhook_state {
    VAPORHOOK_STATE_EMPTY = 0,
    VAPORHOOK_STATE_PREPARED = 1,
    VAPORHOOK_STATE_INSTALLED = 2,
    VAPORHOOK_STATE_INCONSISTENT = 3,
} vaporhook_state_t;

enum { VAPORHOOK_MAX_HOOKS = 64 };

/*
 * Calls that use the same engine must be externally serialized. In
 * particular, destroy may run only after all other calls have returned and no
 * later call will use the engine pointer.
 */
vaporhook_status_t vaporhook_create(vaporhook_engine_t **engine_out);

/*
 * Builds an executable trampoline without modifying target code. The caller
 * must keep target and detour valid and prevent target-byte changes while
 * prepare runs and until the engine is destroyed.
 */
vaporhook_status_t vaporhook_prepare(vaporhook_engine_t *engine, void *target, void *detour,
                                    void **trampoline_out);

/*
 * The caller must stop execution in every target, detour and trampoline while
 * install/uninstall runs. All prepared hooks are committed as one set.
 */
vaporhook_status_t vaporhook_install(vaporhook_engine_t *engine);
vaporhook_status_t vaporhook_uninstall(vaporhook_engine_t *engine);

/* Refuses to destroy installed or inconsistent engines. */
vaporhook_status_t vaporhook_destroy(vaporhook_engine_t *engine);

vaporhook_state_t vaporhook_state(const vaporhook_engine_t *engine);
size_t vaporhook_hook_count(const vaporhook_engine_t *engine);
const char *vaporhook_error_message(const vaporhook_engine_t *engine);
const char *vaporhook_status_string(vaporhook_status_t status);

#ifdef __cplusplus
}
#endif

#endif
