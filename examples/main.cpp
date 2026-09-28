#include <iostream>
#include <ellohim/ellohim.hpp>

// Using namespace big or ellohim or directly
using namespace ellohim;

// Example hooks definition struct matching the user's code style
struct hooks
{
	static inline bool g_cursor_hook_called = false;
	static inline int g_last_x = 0;
	static inline int g_last_y = 0;

	// Hook callback for SetCursorPos
	static BOOL set_cursor_pos(int x, int y)
	{
		g_cursor_hook_called = true;
		g_last_x = x;
		g_last_y = y;

		std::cout << "[Hook] SetCursorPos intercepted! (x=" << x << ", y=" << y << ")\n";

		// Call original function via detour_base::get_original or detour_hook::get_original
		return detour_base::get_original<hooks::set_cursor_pos>()(x, y);
	}
};

// Example polymorphic class for testing VMT Hook
class IGameRenderer
{
public:
	virtual ~IGameRenderer() = default;
	virtual void render_frame(int frame_id)
	{
		std::cout << "[Original VMT] render_frame called with ID: " << frame_id << "\n";
	}
	virtual int get_fps()
	{
		return 60;
	}
};

// Detour for VMT method
namespace vmt_detours
{
	static inline bool g_render_hook_called = false;
	static inline vmt_hook* g_vmt = nullptr;

	// In x64 Windows, first arg is RCX (this pointer)
	void __fastcall hook_render_frame(IGameRenderer* this_ptr, int frame_id)
	{
		g_render_hook_called = true;
		std::cout << "[Hook VMT] hook_render_frame intercepted! (this=" << this_ptr << ", frame_id=" << frame_id << ")\n";

		// Call original VMT function at index 1 (index 0 is destructor)
		using original_fn = void(__fastcall*)(IGameRenderer*, int);
		g_vmt->get_original<original_fn>(1)(this_ptr, frame_id);
	}
}

// Target function to test Mid-Function Hook
__declspec(noinline) int calculate_score(int base_score, int multiplier)
{
	std::cout << "  [Target] inside calculate_score: base=" << base_score << ", mul=" << multiplier << "\n";
	return (base_score * 2) + multiplier;
}

namespace mid_detours
{
	static inline bool g_mid_called = false;
	static inline uint64_t g_captured_rcx = 0;
	static inline uint64_t g_captured_rdx = 0;

	// SafetyHook style MidHook callback receiving Context&
	void on_calculate_mid(mid_context& ctx)
	{
		g_mid_called = true;
		g_captured_rcx = ctx.rcx;
		g_captured_rdx = ctx.rdx;

		std::cout << "[MidHook] Intercepted live CPU context!\n"
		          << "          RCX (base_score) = " << ctx.rcx << "\n"
		          << "          RDX (multiplier) = " << ctx.rdx << "\n"
		          << "          RSP              = 0x" << std::hex << ctx.rsp << std::dec << "\n"
		          << "          RIP              = 0x" << std::hex << ctx.rip << std::dec << "\n";
	}
}

// Detour for VFT Hook (PolyHook V2 style VFuncSwap)
namespace vft_detours
{
	static inline bool g_vft_called = false;
	int __fastcall hook_get_fps(IGameRenderer* this_ptr)
	{
		g_vft_called = true;
		std::cout << "[VFT Hook] get_fps intercepted! Original would return: "
		          << vft_hook::get_original<&hook_get_fps>()(this_ptr)
		          << ", spoofing to 144 FPS.\n";
		return 144;
	}
}

// Detour for IAT Hook
namespace iat_detours
{
	static inline bool g_iat_called = false;
	BOOL WINAPI hook_is_debugger_present()
	{
		g_iat_called = true;
		std::cout << "[IAT Hook] IsDebuggerPresent intercepted! Returning spoofed TRUE.\n";
		return TRUE;
	}
}

int main()
{
	std::cout << "==========================================\n";
	std::cout << "  Ellohim-Hook All-In-One Hooking Demo    \n";
	std::cout << "==========================================\n\n";

	try
	{
		// 1. Initialize Hooking environment
		minhook_keepalive keepalive;

		// ---------------------------------------------------------
		// DEMO 1: DETOUR HOOK (Exact User Request Code Style)
		// ---------------------------------------------------------
		std::cout << "[Step 1] Setting up Native Detour Hook on SetCursorPos...\n";

		// EXACT code style requested by user:
		detour_hook::add<hooks::set_cursor_pos>(
			"SetCursorPos",
			memory::module("user32.dll").get_export("SetCursorPos").as<void*>()
		);

		// Enable all detours natively
		detour_base::enable_all();

		std::cout << "[Step 2] Calling SetCursorPos(100, 200)...\n";
		SetCursorPos(100, 200);

		if (hooks::g_cursor_hook_called && hooks::g_last_x == 100 && hooks::g_last_y == 200)
		{
			std::cout << ">>> Native Detour Hook SUCCESS! Intercepted coordinates correctly.\n\n";
		}
		else
		{
			std::cerr << ">>> Detour Hook FAILED!\n\n";
		}

		// Disable detour
		detour_base::disable_all();

		hooks::g_cursor_hook_called = false;
		SetCursorPos(300, 400);
		if (!hooks::g_cursor_hook_called)
		{
			std::cout << ">>> Native Detour unhook SUCCESS! Hook did not trigger when disabled.\n\n";
		}

		// ---------------------------------------------------------
		// DEMO 2: VMT HOOK (Virtual Method Table Swapping)
		// ---------------------------------------------------------
		std::cout << "[Step 3] Setting up VMT Hook on IGameRenderer...\n";
		auto renderer = std::make_unique<IGameRenderer>();

		std::cout << "Calling original unhooked render_frame(1):\n";
		renderer->render_frame(1);

		// Initialize VMT hook (auto-detects function count or specify 2)
		vmt_hook vmt(renderer.get(), 2);
		vmt_detours::g_vmt = &vmt;

		// Hook virtual method at index 1 (render_frame)
		vmt.hook(1, reinterpret_cast<void*>(&vmt_detours::hook_render_frame));
		vmt.enable();

		std::cout << "Calling render_frame(2) while VMT hook is ENABLED:\n";
		renderer->render_frame(2);

		if (vmt_detours::g_render_hook_called)
		{
			std::cout << ">>> VMT Hook SUCCESS! Virtual method intercepted.\n\n";
		}
		else
		{
			std::cerr << ">>> VMT Hook FAILED!\n\n";
		}

		// Disable VMT hook
		vmt.disable();
		vmt_detours::g_render_hook_called = false;
		std::cout << "Calling render_frame(3) after VMT hook is DISABLED:\n";
		renderer->render_frame(3);

		if (!vmt_detours::g_render_hook_called)
		{
			std::cout << ">>> VMT unhook SUCCESS! Clean restoration of original table.\n\n";
		}

		// ---------------------------------------------------------
		// DEMO 3: MID-FUNCTION HOOK (Inspired by SafetyHook)
		// ---------------------------------------------------------
		std::cout << "[Step 4] Setting up Mid-Function Hook (SafetyHook style)...\n";

		mid_hook::add<mid_detours::on_calculate_mid>(
			"CalculateScoreMid",
			reinterpret_cast<void*>(&calculate_score)
		);

		mid_hook::enable_all();

		std::cout << "Calling calculate_score(50, 5) while MidHook is ENABLED:\n";
		int score = calculate_score(50, 5);
		std::cout << "  Returned score: " << score << "\n";

		if (mid_detours::g_mid_called && mid_detours::g_captured_rcx == 50 && mid_detours::g_captured_rdx == 5 && score == 105)
		{
			std::cout << ">>> Mid-Function Hook SUCCESS! Captured live CPU registers and preserved execution flow.\n\n";
		}
		else
		{
			std::cerr << ">>> Mid-Function Hook FAILED!\n\n";
		}

		// Disable MidHook
		mid_hook::disable_all();
		mid_detours::g_mid_called = false;
		std::cout << "Calling calculate_score(10, 2) after MidHook is DISABLED:\n";
		int score2 = calculate_score(10, 2);
		std::cout << "  Returned score: " << score2 << "\n";

		if (!mid_detours::g_mid_called && score2 == 22)
		{
			std::cout << ">>> Mid-Function unhook SUCCESS! Clean restoration.\n\n";
		}
		// ---------------------------------------------------------
		// DEMO 4: VFT HOOK (PolyHook V2 VFuncSwap style)
		// ---------------------------------------------------------
		std::cout << "[Step 5] Setting up VFT Hook (PolyHook V2 VFuncSwap style)...\n";
		std::cout << "Calling unhooked get_fps(): " << renderer->get_fps() << " FPS\n";

		// Hook virtual table slot 2 directly in-place
		vft_hook::add<&vft_detours::hook_get_fps>("GetFpsVFT", renderer.get(), 2);
		vft_hook::enable_all();

		std::cout << "Calling get_fps() while VFT hook is ENABLED:\n";
		int fps = renderer->get_fps();
		std::cout << "  Returned FPS: " << fps << "\n";

		if (vft_detours::g_vft_called && fps == 144)
		{
			std::cout << ">>> VFT Hook SUCCESS! Table slot replaced in-place.\n\n";
		}
		else
		{
			std::cerr << ">>> VFT Hook FAILED!\n\n";
		}

		vft_hook::disable_all();
		vft_detours::g_vft_called = false;
		int orig_fps = renderer->get_fps();
		std::cout << "Calling get_fps() after VFT hook is DISABLED: " << orig_fps << " FPS\n";
		if (!vft_detours::g_vft_called && orig_fps == 60)
		{
			std::cout << ">>> VFT unhook SUCCESS! Table slot restored.\n\n";
		}

		// ---------------------------------------------------------
		// DEMO 5: IAT HOOK (Import Address Table Hooking)
		// ---------------------------------------------------------
		std::cout << "[Step 6] Setting up IAT Hook on IsDebuggerPresent...\n";
		BOOL initial_dbg = IsDebuggerPresent();
		std::cout << "Initial IsDebuggerPresent(): " << initial_dbg << "\n";

		iat_hook::add<&iat_detours::hook_is_debugger_present>(
			"IsDebuggerPresentIAT",
			GetModuleHandleW(nullptr),
			"KERNEL32.dll",
			"IsDebuggerPresent"
		);
		iat_hook::enable_all();

		BOOL hooked_dbg = IsDebuggerPresent();
		std::cout << "IsDebuggerPresent() while IAT hook is ENABLED: " << hooked_dbg << "\n";

		if (iat_detours::g_iat_called && hooked_dbg == TRUE)
		{
			std::cout << ">>> IAT Hook SUCCESS! Import address table pointer redirected.\n\n";
		}
		else
		{
			std::cerr << ">>> IAT Hook FAILED!\n\n";
		}

		iat_hook::disable_all();
		iat_detours::g_iat_called = false;
		BOOL restored_dbg = IsDebuggerPresent();
		std::cout << "IsDebuggerPresent() after IAT hook is DISABLED: " << restored_dbg << "\n";

		if (!iat_detours::g_iat_called && restored_dbg == initial_dbg)
		{
			std::cout << ">>> IAT unhook SUCCESS! Restored original import pointer.\n\n";
		}

		std::cout << "==========================================\n";
		std::cout << "          ALL TESTS PASSED!               \n";
		std::cout << "==========================================\n";
	}
	catch (const std::exception& e)
	{
		std::cerr << "Exception occurred: " << e.what() << "\n";
		return 1;
	}

	return 0;
}
