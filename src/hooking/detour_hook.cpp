#include "ellohim/hooking/detour_hook.hpp"
#include "core/buffer.hpp"
#include "core/trampoline.hpp"
#include "core/thread_freezer.hpp"
#include <cstring>
namespace ellohim
{
	static bool bytes_equal(const void* target, const void* expected, size_t size) noexcept
	{
		__try { return std::memcmp(target, expected, size) == 0; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	}
	struct detour_hook::core_info
	{
		core::hook_info hook;
	};
	detour_hook::detour_hook(std::string_view name, void* target, void* detour, bool register_hook) :
	    detour_base(name, register_hook),
	    m_target(target),
	    m_detour(detour),
	    m_info(std::make_unique<core_info>())
	{
		if (!target || !detour)
			throw std::runtime_error("Null detour target/callback");
		// Patch the actual entry, including another hook's branch if present; do not chase into its callback.
		m_slot = core::allocate_slot(target);
		if (!m_slot)
		{
			const auto near_error = GetLastError();
			m_slot = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!m_slot)
				throw std::runtime_error(std::format("Hook '{}': near allocation failed ({}) and absolute fallback allocation failed ({})", name, near_error, GetLastError()));
			logger::warning("Hook '{}': near allocation failed ({}); trying absolute entry patch", name, near_error);
		}
		if (!core::create_trampoline(target, detour, m_slot, m_info->hook))
		{
			const auto failed_slot = reinterpret_cast<uintptr_t>(m_slot);
			core::free_slot(m_slot);
			m_slot = nullptr;
			throw std::runtime_error(std::format("Hook '{}': prolog cannot be safely relocated at {:p}, trampoline 0x{:X}", name, target, failed_slot));
		}
		m_trampoline = m_slot;
		m_patch_size = m_info->hook.patch_size;
		m_stolen_size = m_info->hook.stolen_size;
		SYSTEM_INFO system{};
		GetSystemInfo(&system);
		// A single protection value cannot restore two differently protected pages.
		if (reinterpret_cast<uintptr_t>(target) % system.dwPageSize + m_patch_size > system.dwPageSize)
		{
			core::free_slot(m_slot);
			m_slot = nullptr;
			throw std::runtime_error("Entry patch crosses a page boundary");
		}
		DWORD previous{};
		if (!VirtualProtect(m_slot, 512, PAGE_EXECUTE_READ, &previous))
		{
			core::free_slot(m_slot);
			m_slot = nullptr;
			throw std::runtime_error("Could not seal trampoline memory");
		}
		std::memcpy(m_original_bytes, m_info->hook.original_bytes, m_stolen_size);
		std::memcpy(m_patch_bytes, m_info->hook.patch_bytes, m_patch_size);
		logger::info("Hook '{}': target {:p}, trampoline {:p}, patch {} bytes", name, target, m_slot, m_patch_size);
	}
	detour_hook::~detour_hook() noexcept
	{
		// Callers must stop hook callbacks before destroying/unloading their code.
		if (m_enabled && !disable())
		{
			logger::error("Hook '{}' could not be disabled; retaining trampoline", m_name);
			return;
		}
		core::free_slot(m_slot);
	}
	bool detour_hook::enable()
	{
		if (m_enabled)
			return true;
		bool patched = false;
		DWORD error = ERROR_SUCCESS;
		{
			DWORD protection{};
			if (!bytes_equal(m_target, m_original_bytes, m_stolen_size))
				error = ERROR_INVALID_DATA;
			else if (!VirtualProtect(m_target, m_patch_size, PAGE_EXECUTE_READWRITE, &protection))
				error = GetLastError();
			else
			{
				{
					core::thread_freezer freezer;
					if (freezer.relocate(m_info->hook, true))
					{
						std::memcpy(m_target, m_patch_bytes, m_patch_size);
						if (!FlushInstructionCache(GetCurrentProcess(), m_target, m_patch_size)) std::terminate();
						patched = true;
					}
				}
				DWORD ignored{};
				if (!VirtualProtect(m_target, m_patch_size, protection, &ignored)) std::terminate();
			}
		}
		if (!patched)
			throw std::runtime_error(std::format("Hook '{}': patch aborted (error {} or thread inside relocated instruction)", m_name, error));
		m_enabled = true;
		return true;
	}
	bool detour_hook::disable()
	{
		if (!m_enabled)
			return true;
		try
		{
			if (!bytes_equal(m_target, m_patch_bytes, m_patch_size))
				return false;
			DWORD protection{};
			if (!VirtualProtect(m_target, m_stolen_size, PAGE_EXECUTE_READWRITE, &protection))
				return false;
			bool safe = false;
			{
				core::thread_freezer freezer;
				safe = freezer.relocate(m_info->hook, false);
				if (safe)
				{
					std::memcpy(m_target, m_original_bytes, m_stolen_size);
					if (!FlushInstructionCache(GetCurrentProcess(), m_target, m_stolen_size)) std::terminate();
					m_enabled = false;
				}
			}
			DWORD ignored{};
			if (!VirtualProtect(m_target, m_stolen_size, protection, &ignored)) std::terminate();
			return safe;
		}
		catch (...)
		{
			return false;
		}
	}
	void detour_hook::enable_immediately()
	{
		enable();
	}
	void detour_hook::disable_immediately()
	{
		if (!disable())
			throw std::runtime_error("Could not disable detour");
	}
	void* detour_hook::get_original_ptr()
	{
		return m_trampoline;
	}
	void detour_hook::fix_hook_address()
	{
	}
}


