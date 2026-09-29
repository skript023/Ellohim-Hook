#include "ellohim/hooking/vft_hook.hpp"
#include "ellohim/logger.hpp"
#include "core/pointer_patch.hpp"
#include <algorithm>

namespace ellohim
{
	// Direct VFT assignment: callers must quiesce virtual calls and serialize writers.
	static bool assign_slot(void** slot, void* expected, void* value, bool writable) noexcept
	{
		DWORD protection{};
		if (!writable && !VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &protection))
			return false;
		bool assigned = false;
		__try
		{
			if (*slot == expected)
			{
				*slot = value;
				assigned = true;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		if (!writable)
		{
			DWORD ignored{};
			if (!VirtualProtect(slot, sizeof(void*), protection, &ignored)) std::terminate();
		}
		return assigned;
	}
	vft_hook::vft_hook(std::string_view name, void* instance, std::size_t index, void* detour) :
	    m_name(name),
	    m_detour(detour)
	{
		if (!instance)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': instance pointer is null", m_name));
		}
		if (!m_detour)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': detour pointer is null", m_name));
		}

		void* table{};
		if (!core::read_pointer(static_cast<void**>(instance), table) || !table || index >= 4096)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': virtual table pointer is null", m_name));
		}

		m_slot = static_cast<void**>(table) + index;
		if (!core::read_pointer(m_slot, m_original)) throw std::runtime_error("Invalid pointer slot");
		m_writable = core::pointer_is_writable(m_slot);

		logger::info("Created vft_hook '{}' for slot {:p} (index {}) -> detour {:p}", m_name, static_cast<void*>(m_slot), index, m_detour);
	}

	vft_hook::vft_hook(std::string_view name, void** vtable, std::size_t index, void* detour) :
	    m_name(name),
	    m_detour(detour)
	{
		if (!vtable || index >= 4096)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': vtable pointer is null", m_name));
		}
		if (!m_detour)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': detour pointer is null", m_name));
		}

		m_slot = &vtable[index];
		if (!core::read_pointer(m_slot, m_original)) throw std::runtime_error("Invalid pointer slot");
		m_writable = core::pointer_is_writable(m_slot);

		logger::info("Created vft_hook '{}' for slot {:p} (index {}) -> detour {:p}", m_name, static_cast<void*>(m_slot), index, m_detour);
	}

	vft_hook::~vft_hook() noexcept
	{
		if (m_clear_binding) m_clear_binding(this);
		if (m_enabled)
		{
			disable();
		}

		std::erase(m_vft_hooks, this);
		logger::info("Removed vft_hook '{}'", m_name);
	}

	bool vft_hook::enable()
	{
		if (m_enabled || !m_slot)
			return true;

		if (!assign_slot(m_slot, m_original, m_detour, m_writable))
			return false;

		m_enabled = true;
		return true;
	}

	bool vft_hook::disable()
	{
		if (!m_enabled || !m_slot)
			return true;

		if (!assign_slot(m_slot, m_detour, m_original, m_writable))
			return false;

		m_enabled = false;
		return true;
	}

	bool vft_hook::enable_all()
	{
		bool status = true;
		for (auto* hook : m_vft_hooks)
		{
			status = hook->enable() && status;
		}
		return status;
	}

	bool vft_hook::disable_all()
	{
		bool status = true;
		for (auto* hook : m_vft_hooks)
		{
			status = hook->disable() && status;
		}
		return status;
	}
}
