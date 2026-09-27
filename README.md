# Ellohim-Hook

Modern C++ Hooking Library yang **100% Independent (Zero External Dependencies)**, dirancang dengan code style elegan dan zero overhead, kompatibel dengan arsitektur `Mono Hacking` / `BigBase`, serta mengadopsi best practices dari **SafetyHook** dan **PolyHook V2**.

---

## 🌟 Mengapa Ellohim-Hook Berbeda?

- **100% Independent & Self-Contained**:
  - **TIDAK memerlukan library eksternal** seperti MinHook, Detours, atau submodul lainnya.
  - Memiliki mesin trampoline, memory slot allocator (2GB relative branch range), dan instruction decoder (HDE) bawaan sendiri yang dikompilasi langsung ke dalam static library.
  - Zero CMake FetchContent / git submodules / external `.lib` dependencies.

- **Detour Hook (Native Inline / Trampoline Hook)**:
  - Compile-time static template dispatch (`detour_hook::add<hooks::func>` & `detour_base::get_original<hooks::func>()`), menghasilkan **zero runtime map lookup overhead**.
  - **Thread-Safe Atomic Patching**: Membekukan thread lain dalam proses (`thread_freezer`) saat proses penulisan bytes hook untuk mencegah race condition.
  - **Relocation & JMP Thunk Auto-Resolution** (seperti PolyHook & SafetyHook): Secara otomatis menelusuri jump chain (`0xE9` rel32, `0xEB` rel8, dan `0xFF 0x25` x64 indirect IAT stubs) menuju ke fungsi asli yang sebenarnya sebelum melakukan hook.
  - **RIP-Relative Displacement Adjustment**: Secara otomatis merekalibrasi displacement instruksi 64-bit yang dipindahkan ke dalam buffer trampoline.
  - **SEH Exception-Protected**: Membaca memori target dengan aman menggunakan Structured Exception Handling (`__try / __except`).

- **VMT Hook (Virtual Method Table Swapping)**:
  - Mengganti pointer vtable pada instance object (`*m_object = m_new_table`).
  - **MSVC RTTI Preservation**: Menyalin pointer RTTI Complete Object Locator (`vtable[-1]`), sehingga `typeid` dan `dynamic_cast` tetap berfungsi normal tanpa crash.
  - **Auto Method Count**: Secara otomatis mendeteksi jumlah virtual method menggunakan `VirtualQuery` jika tidak ditentukan secara manual.
  - RAII-safe: Otomatis me-restore vtable asli saat destruktor dipanggil.

- **Mid-Function Hook (`mid_hook`, Inspired by SafetyHook)**:
  - Mengintersepsi eksekusi di tengah-tengah fungsi tanpa mengubah jalannya program.
  - Menyimpan seluruh context register CPU (`mid_context`: RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8-R15, RSP, RFLAGS, serta SIMD XMM0-XMM15).
  - Melewatkan `mid_context&` ke callback `void(mid_context& ctx)` sehingga nilai register dapat dibaca maupun dimodifikasi langsung secara live!
  - Menjalankan kembali instruksi yang digantikan dan melanjutkan eksekusi ke fungsi asli secara transparan.

- **Memory Utilities**:
  - `memory::handle`: Wrapper pointer serbaguna (`as<T*>()`, `as<T&>()`, `as<uintptr_t>()`, `add()`, `sub()`, `rip()`).
  - `memory::module`: Mengambil HMODULE, menghitung `SizeOfImage` dari PE Header, dan mencari export address dengan `get_export("Name")`.
  - `memory::range` & `memory::pattern`: Scan memori dengan signature IDA (`"48 89 5C 24 ? 48 89 6C 24"`).

- **Swap Pointer Hook**:
  - Mengganti pointer fungsi arbitrer / IAT dengan proteksi memori otomatis (`VirtualProtect`).

---

## 🚀 Contoh Penggunaan

### 1. Detour Hook (Sesuai Code Style yang Diminta)

```cpp
#include <ellohim/ellohim.hpp>

// Atau menggunakan namespace big (kompatibel penuh dengan BigBase/Mono Hacking):
// using namespace big;
using namespace ellohim;

// Definisi hook callbacks
struct hooks
{
    static BOOL set_cursor_pos(int x, int y)
    {
        // Custom logic di sini
        std::cout << "Intercepted SetCursorPos(" << x << ", " << y << ")\n";

        // Panggil fungsi original dengan zero lookup overhead:
        return detour_base::get_original<hooks::set_cursor_pos>()(x, y);
    }
};

int main()
{
    // Tambahkan hook persis seperti style yang diinginkan:
    detour_hook::add<hooks::set_cursor_pos>(
        "SetCursorPos",
        memory::module("user32.dll").get_export("SetCursorPos").as<void*>()
    );

    // Aktifkan semua hooks secara native (tanpa library luar)
    detour_base::enable_all();

    // Uji coba hook
    SetCursorPos(500, 300);

    // Nonaktifkan hook
    detour_base::disable_all();

    return 0;
}
```

---

### 2. VMT Hook (Virtual Method Table Swapping)

```cpp
#include <ellohim/ellohim.hpp>

using namespace ellohim;

class IGameRenderer
{
public:
    virtual ~IGameRenderer() = default;
    virtual void render_frame(int frame_id)
    {
        std::cout << "Original render_frame: " << frame_id << "\n";
    }
};

namespace vmt_detours
{
    static inline vmt_hook* g_vmt = nullptr;

    void __fastcall hook_render_frame(IGameRenderer* this_ptr, int frame_id)
    {
        std::cout << "Hooked render_frame called! Frame: " << frame_id << "\n";

        // Panggil original virtual function (index 1)
        using fn_t = void(__fastcall*)(IGameRenderer*, int);
        g_vmt->get_original<fn_t>(1)(this_ptr, frame_id);
    }
}

int main()
{
    auto renderer = std::make_unique<IGameRenderer>();

    // Buat VMT hook (bisa tentukan jumlah method atau 0 untuk auto-detect)
    vmt_hook vmt(renderer.get(), 2);
    vmt_detours::g_vmt = &vmt;

    // Pasang hook pada index ke-1
    vmt.hook(1, reinterpret_cast<void*>(&vmt_detours::hook_render_frame));
    vmt.enable();

    // Panggil method virtual (akan masuk ke hook)
    renderer->render_frame(42);

    // Restore table asli
    vmt.disable();

    return 0;
}
```

---

### 3. Mid-Function Hook (Gaya SafetyHook)

```cpp
#include <ellohim/ellohim.hpp>

using namespace ellohim;

// Callback MidHook menerima live context CPU:
void on_my_mid_hook(mid_context& ctx)
{
    std::cout << "Live register values:\n"
              << "RCX = " << ctx.rcx << "\n"
              << "RDX = " << ctx.rdx << "\n"
              << "RSP = 0x" << std::hex << ctx.rsp << std::dec << "\n";

    // Anda bahkan bisa memodifikasi register jika diperlukan:
    // ctx.rax = 0x1337;
}

int main()
{
    void* target_address = /* alamat instruksi di dalam fungsi */;

    // Daftarkan mid_hook
    mid_hook::add<on_my_mid_hook>("MyMidHook", target_address);
    mid_hook::enable_all();

    // Jalankan kode yang memanggil fungsi tersebut...

    mid_hook::disable_all();
    return 0;
}
```

---

## 📁 Struktur Direktori

```text
Ellohim-Hook/
├── CMakeLists.txt           # Build script mandiri (murni MSVC/Clang + Windows SDK)
├── README.md
├── include/
│   └── ellohim/
│       ├── common.hpp       # Common headers & definitions
│       ├── logger.hpp       # Logging system
│       ├── ellohim.hpp      # Umbrella include
│       ├── hooking.hpp      # Main hooking & compatibility layer (namespace big)
│       ├── memory/
│       │   ├── handle.hpp   # Pointer wrapper, type casting, RIP resolution
│       │   ├── range.hpp    # Memory range operations
│       │   ├── module.hpp   # Module loader, PE parser, export lookup
│       │   └── pattern.hpp  # Signature pattern scanner
│       └── hooking/
│           ├── detour_base.hpp        # Base detour registry & static dispatch
│           ├── detour_hook.hpp        # Detour hook dengan thunk resolution
│           ├── vmt_hook.hpp           # VMT table swapping hook
│           └── swap_pointer_hook.hpp  # Pointer & IAT swap hook
├── src/
│   ├── logger.cpp
│   ├── hooking.cpp
│   ├── memory/
│   │   ├── range.cpp
│   │   ├── module.cpp
│   │   └── pattern.cpp
│   └── hooking/
│       ├── core/                      # Engine Detour Internal (Independent)
│       │   ├── buffer.hpp/.cpp        # 2GB-range virtual memory slot allocator
│       │   ├── trampoline.hpp/.cpp    # Trampoline generator & instruction relocator
│       │   ├── thread_freezer.hpp     # Thread suspension helper untuk atomic patching
│       │   └── hde/                   # Internal length disassembler (hde64 / hde32)
│       ├── detour_base.cpp
│       ├── detour_hook.cpp            # Native detour hook implementation
│       ├── vmt_hook.cpp
│       └── swap_pointer_hook.cpp
└── examples/
    └── main.cpp             # Contoh lengkap & pengujian semua hooks
```

---

## 🛠️ Build & Kompilasi

Library ini hanya membutuhkan compiler yang mendukung **C++20** dan **Windows SDK**:

```bash
# 1. Konfigurasi build (Visual Studio 2022 / 2026 x64)
cmake -B build -G "Visual Studio 18 2026" -A x64

# 2. Build Release
cmake --build build --config Release

# 3. Jalankan demo program
.\build\Release\EllohimHookExample.exe
```
