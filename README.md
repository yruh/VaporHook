# VaporHook

面向 Linux x86 / x86_64 的 inline Hook 库，VaporCore 的运行时 Hook 核心。

## 特性

- 安装前不修改目标代码，先构建跳板（trampoline）
- 一组 Hook 一次提交，失败时还原已写入的部分
- 补丁期间代码页只短暂加写权限，改完立即恢复只读执行
- 不创建也不接受可写可执行（RWX）的代码页
- 卸载不完整时保留跳板，不释放可能仍在运行的代码
- 32 位与 64 位同时构建和测试

## 构建

```bash
make check
```

`make test` 只运行当前架构，`make test32` 运行 32 位测试。

## 使用

```c
#include <vaporhook/vaporhook.h>

vaporhook_engine_t *engine = NULL;
vaporhook_create(&engine);
void *trampoline = NULL;
vaporhook_prepare(engine, (void *)target_fn, (void *)my_detour, &trampoline);
vaporhook_install(engine);   /* 提交本 engine 的全部 Hook */
```

同一 engine 的调用必须由调用方串行化；`install` / `uninstall` 期间，调用方必须暂停所有
可能执行目标、detour 或 trampoline 的线程。VaporCore 由 `HookQuiescence` 负责这个边界。

## 许可证

VaporHook 使用 [GNU AGPL-3.0](LICENSE) 许可证。
