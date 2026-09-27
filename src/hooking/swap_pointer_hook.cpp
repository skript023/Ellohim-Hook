#include "ellohim/hooking/swap_pointer_hook.hpp"
#include "ellohim/logger.hpp"

namespace ellohim
{
	swap_pointer_hook::swap_pointer_hook(std::string_view name, void** target, void* swap) :
	    m_name(name),
	    m_target(target),
	    m_swap(swap)
	{
		logger::info("Created swap_pointer_hook '{}' for target at {:p}", m_name, static_cast<void*>(m_target));
	}

	swap_pointer_hook::~swap_pointer_hook() noexcept
	{
		if (m_enabled)
		{
			disable();
		}
	}

	void swap_pointer_hook::enable()
	{
		if (m_enabled || !m_target)
			return;

		DWORD old_protect{};
		VirtualProtect(m_target, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect);
		m_original = *m_target;
		*m_target = m_swap;
		VirtualProtect(m_target, sizeof(void*), old_protect, &old_protect);

		m_enabled = true;
	}

	void swap_pointer_hook::disable()
	{
		if (!m_enabled || !m_target)
			return;

		DWORD old_protect{};
		VirtualProtect(m_target, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect);
		*m_target = m_original;
		VirtualProtect(m_target, sizeof(void*), old_protect, &old_protect);

		m_enabled = false;
	}
}
