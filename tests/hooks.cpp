#include <ellohim/hooking/detour_hook.hpp>
#include <ellohim/hooking/mid_hook.hpp>
#include <ellohim/hooking/vmt_hook.hpp>
#include "core/trampoline.hpp"
#include <atomic>
#include <thread>
#include <cstring>
#include <iostream>

static void check(bool result, const char* message)
{
	if (!result)
		throw std::runtime_error(message);
}
struct page
{
	uint8_t* data = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	page()
	{
		check(data != nullptr, "Test allocation failed");
		std::memset(data, 0x90, 4096);
	}
	~page()
	{
		VirtualFree(data, 0, MEM_RELEASE);
	}
	void write(std::initializer_list<uint8_t> code, size_t offset = 0)
	{
		std::copy(code.begin(), code.end(), data + offset);
		FlushInstructionCache(GetCurrentProcess(), data, 4096);
	}
};
static int replacement()
{
	return 42;
}
static int mid_seen;
static LPVOID(WINAPI* original_convert)(LPVOID);
static LPVOID WINAPI convert_detour(LPVOID value)
{
	return IsThreadAFiber() ? GetCurrentFiber() : original_convert(value);
}
static void mid(ellohim::mid_context& ctx)
{
	mid_seen = static_cast<int>(ctx.rax);
	ctx.rax = 21;
}
static void preserve(ellohim::mid_context&)
{
	++mid_seen;
}
static int virtual_original(void*)
{
	return 4;
}
static int virtual_replacement(void*)
{
	return 8;
}

int main()
try
{
	ellohim::logger::set_callback([](auto, auto) {
	});
	using fn = int (*)();
	using arg_fn = int (*)(int);
	page code;
	code.write({0xb8, 7, 0, 0, 0, 0xc3});
	auto function = reinterpret_cast<fn>(code.data);
	for (int iteration = 0; iteration < 5; ++iteration)
	{
		ellohim::detour_hook hook("constant", code.data, reinterpret_cast<void*>(&replacement));
		check(function() == 7, "Creation changed target");
		check(hook.enable() && function() == 42, "Detour did not execute");
		check(hook.get_original<fn>()() == 7, "Original trampoline failed");
		check(hook.disable() && function() == 7, "Restoration failed");
	}
	std::cout << "PASS: detour, original call, disable, repeated construction\n";
	code.write({0x85, 0xc9, 0x74, 4, 0x8d, 0x41, 1, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3});
	{
		ellohim::detour_hook hook("conditional", code.data, reinterpret_cast<void*>(&replacement));
		auto original = hook.get_original<arg_fn>();
		check(original(0) == 9 && original(3) == 4, "Conditional branch relocation failed");
	}
	code.write({0xeb, 2, 0x90, 0x90, 0xb8, 11, 0, 0, 0, 0xc3});
	{
		ellohim::detour_hook hook("internal branch", code.data, reinterpret_cast<void*>(&replacement));
		check(hook.get_original<fn>()() == 11, "Internal branch relocation failed");
	}
	const int value = 17;
	std::memcpy(code.data, &value, 4);
	code.write({0x8b, 0x05, 0xea, 0xff, 0xff, 0xff, 0xc3}, 16);
	{
		ellohim::detour_hook hook("negative RIP", code.data + 16, reinterpret_cast<void*>(&replacement));
		check(hook.get_original<fn>()() == 17, "Signed RIP displacement failed");
	}
	std::cout << "PASS: conditional/internal branches and negative RIP-relative load\n";
	// Force the trampoline more than 2 GiB away to exercise the absolute entry patch.
	void* distant_page = nullptr;
	for (uintptr_t address = 0x100000000; address < 0x1000000000 && !distant_page; address += 0x100000000)
		if (std::abs(static_cast<int64_t>(address) - reinterpret_cast<int64_t>(code.data)) > 0x90000000)
			distant_page = VirtualAlloc(reinterpret_cast<void*>(address), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	check(distant_page != nullptr, "Could not reserve distant_page test page");
	code.write({0xb8, 7, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3});
	ellohim::core::hook_info info{};
	check(ellohim::core::create_trampoline(code.data, reinterpret_cast<void*>(&replacement), distant_page, info) && info.patch_size == 14, "Absolute fallback was not generated");
	check(reinterpret_cast<fn>(distant_page)() == 7, "Far trampoline execution failed");
	std::memcpy(code.data, info.patch_bytes, info.patch_size);
	FlushInstructionCache(GetCurrentProcess(), code.data, 32);
	check(function() == 42, "Absolute entry execution failed");
	std::memcpy(code.data, info.original_bytes, info.stolen_size);
	code.write({0x8b, 0x05, 0xea, 0xff, 0xff, 0xff, 0xc3}, 16);
	check(!ellohim::core::create_trampoline(code.data + 16, reinterpret_cast<void*>(&replacement), distant_page, info), "Unreachable RIP operand was silently truncated");
	VirtualFree(distant_page, 0, MEM_RELEASE);
	std::cout << "PASS: distant_page absolute fallback and refusal of unsafe relocation\n";
	code.write({0xb8, 7, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x83, 0xc0, 1, 0xc3});
	{
		ellohim::mid_hook hook("mid RAX", code.data + 5, mid);
		hook.enable();
		check(function() == 22 && mid_seen == 7, "Mid-hook RAX preservation/modification failed");
		hook.disable();
		check(function() == 8, "Mid-hook restoration failed");
	}
	code.write({0x85, 0xc9, 0x90, 0x90, 0x90, 0x90, 0x90, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3});
	{
		ellohim::mid_hook hook("mid flags", code.data + 2, preserve);
		hook.enable();
		auto original = reinterpret_cast<arg_fn>(code.data);
		check(original(0) == 1 && original(1) == 0, "Mid-hook flags failed");
	}
	std::cout << "PASS: mid-hook live RAX, flags, stack alignment and restoration\n";
	void* table[] = {nullptr, reinterpret_cast<void*>(&virtual_original)};
	struct object
	{
		void** table;
	} instance{table + 1};
	{
		ellohim::vmt_hook hook(&instance, 1);
		hook.hook(0, reinterpret_cast<void*>(&virtual_replacement));
		hook.enable();
		check(reinterpret_cast<int (*)(void*)>(instance.table[0])(&instance) == 8, "VMT replacement failed");
		check(hook.get_original<int (*)(void*)>(0)(&instance) == 4, "VMT original failed");
		bool rejected = false;
		try
		{
			hook.hook(SIZE_MAX, nullptr);
		}
		catch (const std::out_of_range&)
		{
			rejected = true;
		}
		check(rejected, "VMT overflow index accepted");
	}
	check(instance.table == table + 1, "VMT destructor did not restore table");
	std::cout << "PASS: VMT dispatch, original, bounds and RAII\n";
	code.write({0xb8, 7, 0, 0, 0, 0xc3});
	std::atomic<bool> stop = false, bad = false;
	ellohim::detour_hook hook("concurrent", code.data, reinterpret_cast<void*>(&replacement));
	std::thread worker([&] {
		while (!stop.load())
		{
			const auto result = function();
			if (result != 7 && result != 42)
				bad = true;
		}
	});
	try
	{
		for (int i = 0; i < 50; ++i)
		{
			hook.enable();
			check(hook.disable(), "Concurrent disable failed");
		}
	}
	catch (...)
	{
		stop = true;
		worker.join();
		throw;
	}
	stop = true;
	worker.join();
	check(!bad, "Concurrent call corrupted");
	std::cout << "PASS: concurrent calls across 50 enable/disable cycles\n";
	{
		auto target = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ConvertThreadToFiber");
		ellohim::detour_hook conversion("ConvertThreadToFiber", reinterpret_cast<void*>(target), reinterpret_cast<void*>(&convert_detour));
		original_convert = conversion.get_original<decltype(original_convert)>();
		conversion.enable();
		auto convert = reinterpret_cast<decltype(original_convert)>(target);
		const auto fiber = convert(nullptr);
		check(fiber && IsThreadAFiber(), "Original Windows fiber conversion failed");
		check(convert(nullptr) == fiber, "Repeated fiber conversion detour failed");
		check(ConvertFiberToThread(), "Could not restore test thread");
		check(conversion.disable(), "Could not restore Windows export");
	}
	std::cout << "PASS: actual Windows ConvertThreadToFiber thunk and original call\n";
	return 0;
}
catch (const std::exception& error)
{
	std::cerr << error.what() << '\n';
	return 1;
}
