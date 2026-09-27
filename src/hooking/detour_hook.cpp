#include "ellohim/hooking/detour_hook.hpp"
#include "ellohim/logger.hpp"
#include "core/buffer.hpp"
#include "core/trampoline.hpp"
#include "core/thread_freezer.hpp"
#include <cstring>

namespace ellohim
{
	static bool resolve_jump_chain(void*& target)
	{
		__try
		{
			auto ptr = memory::handle(target);
			std::size_t max_depth = 16;
			bool resolved = true;

			while (resolved && max_depth-- > 0 && ptr)
			{
				const auto opcode = ptr.as<std::uint8_t&>();
				if (opcode == 0xE9) // jmp rel32
				{
					ptr = ptr.add(1).rip();
				}
				else if (opcode == 0xEB) // jmp rel8
				{
					const auto rel8 = ptr.add(1).as<std::int8_t&>();
					ptr = ptr.add(2).add(rel8);
				}
#if defined(_M_X64) || defined(__x86_64__)
				else if (opcode == 0xFF && ptr.add(1).as<std::uint8_t&>() == 0x25) // jmp qword ptr [rip + disp32]
				{
					auto* target_ptr = ptr.add(2).rip().as<void**>();
					if (target_ptr && *target_ptr)
					{
						ptr = memory::handle(*target_ptr);
					}
					else
					{
						resolved = false;
					}
				}
#endif
				else
				{
					resolved = false;
				}
			}

			target = ptr.as<void*>();
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	detour_hook::detour_hook(std::string_view name, void* target, void* detour) :
	    detour_base(name),
	    m_target(target),
	    m_detour(detour)
	{
		logger::info("Creating native detour hook '{}' at {:p} -> {:p}", m_name, m_target, m_detour);
		if (!m_target)
		{
			throw std::runtime_error(std::format("Failed to create hook '{}': target function pointer is null", m_name));
		}
		if (!m_detour)
		{
			throw std::runtime_error(std::format("Failed to create hook '{}': detour function pointer is null", m_name));
		}

		fix_hook_address();

		m_slot = core::allocate_slot(m_target);
		if (!m_slot)
		{
			throw std::runtime_error(std::format("Failed to allocate 2GB-range memory slot for hook '{}'", m_name));
		}

		core::hook_info info{};
		if (!core::create_trampoline(m_target, m_detour, m_slot, info))
		{
			core::free_slot(m_slot);
			m_slot = nullptr;
			throw std::runtime_error(std::format("Failed to create trampoline for hook '{}' at {:p}", m_name, m_target));
		}

		m_trampoline = info.trampoline;
		m_patch_size = info.patch_size;
		m_stolen_size = info.stolen_size;
		std::memcpy(m_original_bytes, info.original_bytes, info.stolen_size);
		std::memcpy(m_patch_bytes, info.patch_bytes, info.patch_size);

		logger::info("Trampoline for hook '{}' created at {:p}", m_name, m_trampoline);
	}

	detour_hook::~detour_hook() noexcept
	{
		if (m_enabled)
		{
			disable();
		}
		if (m_slot)
		{
			core::free_slot(m_slot);
			m_slot = nullptr;
			m_trampoline = nullptr;
		}
		logger::info("Removed hook '{}'", m_name);
	}

	bool detour_hook::enable()
	{
		if (m_enabled || !m_target)
			return true;

		core::thread_freezer freezer;

		DWORD old_protect{};
		if (!VirtualProtect(m_target, m_patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
		{
			throw std::runtime_error(std::format("VirtualProtect failed while enabling hook '{}'", m_name));
		}

		std::memcpy(m_target, m_patch_bytes, m_patch_size);
		VirtualProtect(m_target, m_patch_size, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_target, m_patch_size);

		m_enabled = true;
		return true;
	}

	bool detour_hook::disable()
	{
		if (!m_enabled || !m_target)
			return true;

		core::thread_freezer freezer;

		DWORD old_protect{};
		if (!VirtualProtect(m_target, m_patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
		{
			return false;
		}

		std::memcpy(m_target, m_original_bytes, m_patch_size);
		VirtualProtect(m_target, m_patch_size, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_target, m_patch_size);

		m_enabled = false;
		return true;
	}

	void detour_hook::enable_immediately()
	{
		enable();
	}

	void detour_hook::disable_immediately()
	{
		disable();
	}

	void* detour_hook::get_original_ptr()
	{
		return m_trampoline;
	}

	void detour_hook::fix_hook_address()
	{
		if (!resolve_jump_chain(m_target))
		{
			logger::error("Exception occurred while fixing hook address for '{}'", m_name);
			throw std::runtime_error(std::format("Failed to fix hook address for '{}'", m_name));
		}
	}
}
