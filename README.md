# Ellohim-Hook 🎣

A modern, fast, and completely self-contained C++20 universal hooking library for Windows x64.
Whether you're doing game modding, malware analysis, reverse engineering, or system instrumentation, Ellohim-Hook provides a robust, zero-dependency hooking engine powered internally by the [Zydis](https://github.com/zyantific/zydis) disassembler.

Before diving in, be sure to check out our [Lifecycle and Concurrency Contract](INTEGRATION.md) for best practices on integration.

---

## ✨ Features & How It Works

Ellohim-Hook is designed to be a universal toolkit. It doesn't rely on MinHook or Detours. Everything from the trampoline allocation to instruction relocation is built from scratch.

- **Native Detour Engine**: The core inline hook. When enabled, it securely suspends running threads, replaces the first 5 bytes of a target function with a relative jump (`0xE9`), and safely relocates any stolen instructions (including RIP-relative ones) into a dynamically allocated trampoline buffer located within $\pm 2$ GB of the target memory.
- **Zydis Powered Relocation**: To ensure 100% accurate instruction length decoding and displacement recalibration during detouring, Ellohim-Hook ships with Zydis v4.1.0 (included in `vendor/zydis` for instant offline building).
- **Zero Runtime Overhead**: The callback architecture uses compile-time static template dispatch (`detour_hook::add<my_func>`), which entirely eliminates the need for slow runtime `std::map` lookups to find the original function pointer.
- **Thread & Exception Safe**: Includes RAII thread freezing to prevent race conditions during patching, and uses Structured Exception Handling (`__try / __except`) when probing target memory.
- **Universal Drop-In**: Comes with a clean, extensible C++20 API. (For developers coming from `BigBase` or `Mono Hacking`, it's also 100% drop-in compatible via `namespace big`).

---

## 🧰 The Hook Arsenal

We’ve packed this library with every type of hook you'll ever need for game modding, instrumentation, or reverse engineering:

- **Detour Hook (`detour_hook`)**: The classic 5-byte inline hook. Safe thread suspension, instruction relocation, and seamless trampoline execution.
- **VMT Hook (`vmt_hook`)**: Virtual Method Table shadowing. Copies the table, preserves MSVC RTTI (`vtable[-1]`), and swaps the instance pointer. Super safe, zero memory protection changes needed.
- **VFT Hook (`vft_hook`)**: PolyHook V2-style VFuncSwap. Patches the class's original virtual table slot in-place with `VirtualProtect`. Affects all instances of the class globally!
- **IAT Hook (`iat_hook`)**: Import Address Table hooking. Give it a module and a DLL export name, and it'll parse the PE headers and swap the import pointer for you.
- **Mid-Function Hook (`mid_hook`)**: Inspired by SafetyHook. Intercept execution at any instruction boundary! Captures the live 64-bit CPU context (RAX-R15, RFLAGS, XMM0-15, RSP, RIP) and lets you inspect or modify it before resuming seamlessly.
- **Swap Pointer Hook (`swap_pointer_hook`)**: Atomic, thread-safe replacement for arbitrary pointers.

Need memory utilities? We've got those too: `memory::module` (PE parser & exports), `memory::pattern` (IDA signature scanning), and `memory::handle` (pointer wrapper).

---

## 🚀 Quick Start Examples

### 1. Detour Hook (The Classic)
```cpp
#include <ellohim/ellohim.hpp>
using namespace ellohim;

struct hooks {
    static BOOL set_cursor_pos(int x, int y) {
        std::cout << "Intercepted SetCursorPos(" << x << ", " << y << ")\n";
        
        // Call the original function with zero lookup overhead!
        return detour_base::get_original<hooks::set_cursor_pos>()(x, y);
    }
};

int main() {
    // 1. Register the hook
    detour_hook::add<hooks::set_cursor_pos>(
        "SetCursorPos",
        memory::module("user32.dll").get_export("SetCursorPos").as<void*>()
    );

    // 2. Enable it
    detour_base::enable_all();

    SetCursorPos(500, 300); // Triggers our hook!
    
    detour_base::disable_all();
    return 0;
}
```

### 2. VMT Hook (Table Shadowing)
```cpp
class IGameRenderer {
public:
    virtual ~IGameRenderer() = default;
    virtual void render_frame(int frame_id) { /* ... */ }
};

namespace vmt_detours {
    static inline vmt_hook* g_vmt = nullptr;
    void __fastcall hook_render_frame(IGameRenderer* this_ptr, int frame_id) {
        std::cout << "Hooked render_frame!\n";
        // Call original at index 1
        g_vmt->get_original<void(__fastcall*)(IGameRenderer*, int)>(1)(this_ptr, frame_id);
    }
}

// Inside your init function:
vmt_hook vmt(renderer_instance, 2); // 2 virtual methods
vmt_detours::g_vmt = &vmt;
vmt.hook(1, reinterpret_cast<void*>(&vmt_detours::hook_render_frame));
vmt.enable();
```

### 3. VFT Hook (In-Place VFuncSwap)
```cpp
int __fastcall hook_get_fps(IGameRenderer* this_ptr) {
    return 144; // Spoof FPS globally for all instances!
}

// Hook virtual table slot 2 directly:
vft_hook::add<&hook_get_fps>("GetFpsVFT", renderer_instance, 2);
vft_hook::enable_all();
```

### 4. Mid-Function Hook (Context Capture)
```cpp
void on_render_mid(mid_context& ctx) {
    std::cout << "Live register values:\n"
              << "RCX = " << ctx.rcx << "\n"
              << "RSP = 0x" << std::hex << ctx.rsp << std::dec << "\n";
              
    // You can even modify registers on the fly!
    // ctx.rax = 1337;
}

// Intercept execution anywhere in the function!
mid_hook::add<on_render_mid>("RenderMid", target_address);
mid_hook::enable_all();
```

### 5. IAT Hook (Import Hooking)
```cpp
BOOL WINAPI hook_is_debugger_present() {
    return TRUE; // Always trick the game into thinking a debugger is attached
}

iat_hook::add<&hook_is_debugger_present>(
    "IsDebuggerPresentIAT",
    GetModuleHandleW(nullptr), // The module to patch
    "KERNEL32.dll",            // The DLL it imports from
    "IsDebuggerPresent"        // The function name
);
iat_hook::enable_all();
```

---

## 🛠️ Building

Ellohim-Hook requires a compiler with **C++20** support and the **Windows SDK**. Zydis is pre-configured in `vendor/zydis`, so CMake will build right out of the box with zero internet connection required.

```bash
# 1. Configure the project
cmake -B build -G "Visual Studio 18 2026" -A x64

# 2. Build in Release mode
cmake --build build --config Release

# 3. Run the all-in-one demo tests!
.\build\Release\EllohimHookExample.exe
```
