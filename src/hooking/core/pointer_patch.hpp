#pragma once
#include <windows.h>
#include <cstdint>
#include <exception>
#include <atomic>

namespace ellohim::core
{
	inline bool pointer_is_writable(void** target) noexcept
	{
		MEMORY_BASIC_INFORMATION region{};
		return VirtualQuery(target, &region, sizeof(region)) &&
		    region.State == MEM_COMMIT && !(region.Protect & PAGE_GUARD) &&
		    (region.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
	}
	inline bool atomic_pointer_exchange(void** target, void* expected, void* replacement) noexcept
	{
		static_assert(std::atomic_ref<void*>::is_always_lock_free);
		return std::atomic_ref<void*>(*target).compare_exchange_strong(expected, replacement);
	}
	// Lifecycle operations must be serialized; the target allocation must stay alive.
	inline bool read_pointer(void** target, void*& value) noexcept
	{
		if (!target || reinterpret_cast<uintptr_t>(target) % alignof(void*)) return false;
		__try { value = *target; return true; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	}
	inline bool exchange_pointer(void** target, void* expected, void* replacement, bool writable = false) noexcept
	{
		if (!target || reinterpret_cast<uintptr_t>(target) % alignof(void*)) return false;
		if (writable) return atomic_pointer_exchange(target, expected, replacement);
		DWORD protection{};
		if (!VirtualProtect(target, sizeof(void*), PAGE_EXECUTE_READWRITE, &protection)) return false;
		bool exchanged = false;
		__try
		{
			exchanged = atomic_pointer_exchange(target, expected, replacement);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		DWORD ignored{};
		if (!VirtualProtect(target, sizeof(void*), protection, &ignored)) std::terminate();
		return exchanged;
	}
}
