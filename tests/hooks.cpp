#include <ellohim/hooking/detour_hook.hpp>
#include <ellohim/hooking/mid_hook.hpp>
#include <ellohim/hooking/vmt_hook.hpp>
#include <ellohim/hooking.hpp>
#include <ellohim/hooking/swap_pointer_hook.hpp>
#include <ellohim/hooking/vft_hook.hpp>
#include <ellohim/hooking/iat_hook.hpp>
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
static int pointer_original() { return 7; }
static int pointer_other() { return 99; }
struct controlled_hook : ellohim::detour_base
{
	bool fail_enable{}, fail_disable{}, throws{};
	controlled_hook() : detour_base("controlled") {}
	bool enable() override
	{
		if (throws) throw std::runtime_error("Injected activation failure");
		if (fail_enable) return false;
		m_enabled = true; return true;
	}
	bool disable() override { if (fail_disable) return false; m_enabled = false; return true; }
	void* get_original_ptr() override { return nullptr; }
};
static void lifecycle_tests()
{
	controlled_hook existing, first, failing;
	existing.enable();
	failing.fail_enable = true;
	check(!ellohim::detour_base::enable_all(), "Batch failure was lost");
	check(existing.is_enabled() && !first.is_enabled(), "Batch rollback changed preexisting hook");
	failing.throws = true;
	bool rejected = false;
	try { ellohim::detour_base::enable_all(); } catch (...) { rejected = true; }
	check(rejected && !first.is_enabled(), "Exception did not roll back batch");
	failing.throws = false;
	{
		ellohim::hooking manager;
		failing.fail_enable = false;
		manager.enable();
		first.fail_disable = true;
		rejected = false;
		try { manager.disable(); } catch (...) { rejected = true; }
		check(rejected && manager.is_enabled(), "Manager lost partial enabled state");
		first.fail_disable = false;
		manager.disable();
	}
	check(ellohim::detour_base::hooks().size() == 3, "Manager deleted externally owned hooks");
}
static void pointer_tests()
{
	using fn = int (*)();
	void* original = reinterpret_cast<void*>(&pointer_original);
	void* replacement_ptr = reinterpret_cast<void*>(&replacement);
	std::atomic<void*> slot{original};
	ellohim::swap_pointer_hook hook("atomic slot", slot, replacement_ptr);
	std::atomic<bool> stop{false}, bad{false};
	std::atomic<unsigned> ready{0};
	std::atomic<size_t> calls{0};
	std::vector<std::jthread> readers;
	for (int i = 0; i < 4; ++i)
		readers.emplace_back([&](std::stop_token token) {
			++ready;
			while (!stop.load() && !token.stop_requested())
			{
				const auto result = reinterpret_cast<fn>(slot.load())();
				if (result != 7 && result != 42) bad = true;
				if (hook.get_original<fn>()() != 7) bad = true;
				++calls;
			}
		});
	while (ready != 4) std::this_thread::yield();
	for (int i = 0; i < 100000; ++i) { hook.enable(); hook.disable(); }
	stop = true;
	readers.clear();
	check(!bad && calls > 0 && slot == original, "Atomic dispatch corrupted under contention");
	hook.enable();
	slot = reinterpret_cast<void*>(&pointer_other);
	bool rejected = false;
	try { hook.disable(); } catch (...) { rejected = true; }
	check(rejected && hook.is_enabled() && reinterpret_cast<fn>(slot.load())() == 99, "Restore overwrote another hook");
	slot = replacement_ptr;
	hook.disable();
	alignas(std::atomic_ref<void*>::required_alignment) void* writable = original;
	ellohim::swap_pointer_hook raw("writable slot", &writable, replacement_ptr);
	raw.enable();
	check(reinterpret_cast<fn>(ellohim::swap_pointer_hook::load_target(&writable))() == 42, "Writable atomic_ref swap failed");
	raw.disable();
	stop = false;
	std::jthread raw_reader([&](std::stop_token token) {
		while (!stop && !token.stop_requested())
		{
			const auto result = reinterpret_cast<fn>(ellohim::swap_pointer_hook::load_target(&writable))();
			if (result != 7 && result != 42) bad = true;
		}
	});
	for (int i = 0; i < 20000; ++i) { raw.enable(); raw.disable(); }
	stop = true;
	raw_reader.join();
	check(!bad, "atomic_ref readers observed a corrupted pointer");
	page storage;
	auto** readonly_slot = reinterpret_cast<void**>(storage.data);
	*readonly_slot = original;
	DWORD previous{};
	check(VirtualProtect(storage.data, 4096, PAGE_READONLY, &previous) != FALSE, "Cannot protect test slot");
	ellohim::swap_pointer_hook protected_hook("readonly slot", readonly_slot, replacement_ptr);
	protected_hook.enable();
	check(reinterpret_cast<fn>(*readonly_slot)() == 42, "Readonly slot swap failed");
	protected_hook.disable();
	MEMORY_BASIC_INFORMATION region{};
	VirtualQuery(readonly_slot, &region, sizeof(region));
	check(region.Protect == PAGE_READONLY && *readonly_slot == original, "Readonly protection/original not restored");
	{
		ellohim::vft_hook vft("slot", readonly_slot, 0, replacement_ptr);
		check(vft.enable() && reinterpret_cast<fn>(*readonly_slot)() == 42, "VFT enable failed");
		check(vft.disable() && *readonly_slot == original, "VFT disable failed");
	}
	bool invalid_rejected = false;
	try { ellohim::swap_pointer_hook invalid("invalid", reinterpret_cast<void**>(storage.data + 1), replacement_ptr); }
	catch (...) { invalid_rejected = true; }
	check(invalid_rejected, "Misaligned pointer accepted");
	std::cout << "PASS: 100000 atomic swaps with four readers, conflicts, writable and readonly slots\n";
}
static void iat_tests()
{
	page image;
	std::memset(image.data, 0, 4096);
	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data);
	dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 128;
	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data + 128);
	nt->Signature = IMAGE_NT_SIGNATURE;
	nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
	nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt->OptionalHeader.SizeOfImage = 4096;
	nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {512, 40};
	auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data + 512);
	desc->Name = 600; desc->OriginalFirstThunk = 640; desc->FirstThunk = 672;
	std::memcpy(image.data + 600, "test.dll", 9);
	auto* names = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data + 640);
	names->u1.AddressOfData = 704;
	std::memcpy(image.data + 706, "Example", 8);
	auto** slot = reinterpret_cast<void**>(image.data + 672);
	*slot = reinterpret_cast<void*>(&pointer_original);
	{
		ellohim::iat_hook hook("synthetic image", reinterpret_cast<HMODULE>(image.data), "test.dll", "Example", reinterpret_cast<void*>(&replacement));
		check(hook.enable() && reinterpret_cast<int(*)()>(*slot)() == 42, "IAT enable failed");
		check(hook.disable() && reinterpret_cast<int(*)()>(*slot)() == 7, "IAT restore failed");
	}
	desc->OriginalFirstThunk = 0;
	bool rejected = false;
	try { ellohim::iat_hook hook("missing INT", reinterpret_cast<HMODULE>(image.data), "test.dll", "Example", reinterpret_cast<void*>(&replacement)); }
	catch (...) { rejected = true; }
	check(rejected, "Loaded IAT addresses were treated as name RVAs");
	desc->OriginalFirstThunk = 640; desc->Name = 4095; image.data[4095] = 'x';
	rejected = false;
	try { ellohim::iat_hook hook("unterminated name", reinterpret_cast<HMODULE>(image.data), "test.dll", "Example", reinterpret_cast<void*>(&replacement)); }
	catch (...) { rejected = true; }
	check(rejected, "Out-of-image import string accepted");
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
	lifecycle_tests();
	pointer_tests();
	iat_tests();
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
