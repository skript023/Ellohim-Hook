Source: https://github.com/skript023/Ellohim-Hook
Snapshot: 44dbddaf1ca2a52f3755ed4ec7118f7c7b29f31f

This integration targets Windows x64. Native detours use a bounded VirtualAlloc2
request with a VirtualQuery fallback over the rel32 range. A distant allocation
uses a 14-byte absolute entry patch when the prolog supports relocation. A
RIP-relative operand outside signed disp32 range is rejected, never truncated.
LOOP/JRCXZ and instructions unsupported by the bundled HDE decoder are rejected.

Mid-hooks share the detour relocator and preserve general registers, RFLAGS,
and XMM0-XMM15. RSP and RIP are snapshots, not writable control-flow overrides.
Callbacks must not throw and must not require preservation of upper AVX/YMM,
AVX-512, or x87 state. These contexts are not supported by this mid-hook ABI.

Hook creation, activation, and destruction must be serialized by the caller.
Thread suspension relocates instruction pointers at known instruction boundaries;
callers must quiesce callbacks before destroying hooks or unloading their module.
It cannot make concurrent module unloading safe by itself.

The Valheim integration keeps MinHook for the separate early graphics capture
path. Game/native detour wrappers, VMT, and the new mid-hook wrapper use Ellohim.
No networking or world/profile flags are changed by the achievement hooks.

Tests: configure with ELLOHIM_BUILD_TESTS=ON, build ellohim_hook_tests, and run
hook-tests/ellohim_hook_tests.exe. This process does not attach to the game.
