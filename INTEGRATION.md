Source: https://github.com/skript023/Ellohim-Hook
Snapshot: 44dbddaf1ca2a52f3755ed4ec7118f7c7b29f31f

This integration targets Windows x64. Native detours use a bounded VirtualAlloc2
request with a VirtualQuery fallback over the rel32 range. A distant allocation
uses a 14-byte absolute entry patch when the prolog supports relocation. A
RIP-relative operand outside signed disp32 range is rejected, never truncated.
Zydis decodes instructions; unsupported relocation forms such as LOOP/JRCXZ
and XBEGIN are rejected. Short branches are widened and internal branch targets
are mapped to instruction boundaries. Entry patches crossing a page boundary
are rejected rather than restoring multiple pages with one protection value.

Mid-hooks share the detour relocator and preserve general registers, RFLAGS,
and XMM0-XMM15. RSP and RIP are snapshots, not writable control-flow overrides.
Callbacks must not throw and must not require preservation of upper AVX/YMM,
AVX-512, or x87 state. These contexts are not supported by this mid-hook ABI.

Hook creation, activation, and destruction must be serialized by the caller.
Thread suspension relocates instruction pointers at known instruction boundaries;
callers must quiesce callbacks before destroying hooks or unloading their module.
It cannot make concurrent module unloading safe by itself.

Pointer slots: swap_pointer_hook stores the original once and uses lock-free
C++ atomics. The std::atomic<void*>& overload needs no WinAPI. For void** slots,
writability is queried once during construction; writable swaps need no WinAPI,
while read-only slots temporarily change protection. Keep allocation and page
protection stable throughout the hook lifetime. Concurrent C++ readers must use
atomic loads (load_target for void**), not ordinary dereferences. Changing a slot
does not wait for callbacks already in flight: keep callback code and state alive
until those calls finish. Lifecycle operations remain caller-serialized.

VFT hooks intentionally use direct pointer assignment, like PolyHook's VFuncSwap.
They do not use atomics or suspend threads. Pause the affected virtual calls while
enabling/disabling VFT hooks. Writable slots need no WinAPI per swap; read-only
slots need VirtualProtect. The expected-value check detects existing conflicts
but is not synchronization with another writer.

The detour registry owns only hooks transferred through add(); directly constructed
hooks retain caller ownership. Mid-hooks use a private, unregistered detour backend.
Manager cleanup retains owned hooks when disable fails. Mid/IAT/VFT hooks are
non-movable so registry pointers and template bindings cannot become stale.
An unrecoverable failure restoring thread contexts or memory protection terminates
the process rather than resuming with partially applied state.

The Valheim integration keeps MinHook for the separate early graphics capture
path. Game/native detour wrappers, VMT, and the new mid-hook wrapper use Ellohim.
No networking or world/profile flags are changed by the achievement hooks.

Tests: configure with ELLOHIM_BUILD_TESTS=ON, build ellohim_hook_tests, and run
ctest --test-dir build -C Debug --output-on-failure. Tests include concurrent
pointer dispatch, lifecycle failures, relocation and malformed IAT metadata.
This process does not attach to the game.
