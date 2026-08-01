# VaporHook

A compact inline-hook library for Linux x86 / x86_64, used as the runtime hook engine
of VaporCore.

## Features

- target code is not modified before installation; a trampoline is built first
- all hooks in a group are committed together, with previously written entries restored
  on failure
- target code pages get write permission only briefly during patching and are restored
  to read-execute immediately after
- writable-and-executable (RWX) code pages are neither created nor accepted
- incomplete removal retains the trampoline instead of freeing code that may still
  be running
- i386 and x86_64 are both built and tested

## Build

```bash
make check
```

`make test` runs the native tests, `make test32` runs the 32-bit tests.

## Usage

```c
#include <vaporhook/vaporhook.h>

vaporhook_engine_t *engine = NULL;
vaporhook_create(&engine);
void *trampoline = NULL;
vaporhook_prepare(engine, (void *)target_fn, (void *)my_detour, &trampoline);
vaporhook_install(engine);   /* commit all hooks in this engine */
```

Calls using the same engine must be serialized by the caller. While `install` / `uninstall`
runs, the caller must quiesce every thread that could execute a target, detour, or
trampoline. VaporCore provides this boundary through `HookQuiescence`.

## License

VaporHook is licensed under [GNU AGPL-3.0](LICENSE).
