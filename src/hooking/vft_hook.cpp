#include "ellohim/hooking/vft_hook.hpp"
#include "ellohim/logger.hpp"
#include <algorithm>

namespace ellohim
{
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

		auto*** obj = static_cast<void***>(instance);
		if (!*obj)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': virtual table pointer is null", m_name));
		}

		m_slot = &((*obj)[index]);
		m_original = *m_slot;

		logger::info("Created vft_hook '{}' for slot {:p} (index {}) -> detour {:p}", m_name, static_cast<void*>(m_slot), index, m_detour);
	}

	vft_hook::vft_hook(std::string_view name, void** vtable, std::size_t index, void* detour) :
	    m_name(name),
	    m_detour(detour)
	{
		if (!vtable)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': vtable pointer is null", m_name));
		}
		if (!m_detour)
		{
			throw std::runtime_error(std::format("Failed to create vft_hook '{}': detour pointer is null", m_name));
		}

		m_slot = &vtable[index];
		m_original = *m_slot;

		logger::info("Created vft_hook '{}' for slot {:p} (index {}) -> detour {:p}", m_name, static_cast<void*>(m_slot), index, m_detour);
	}

	vft_hook::~vft_hook() noexcept
	{
		if (m_enabled)
		{
			disable();
		}

		std::erase(m_vft_hooks, this);
		logger::info("Removed vft_hook '{}'", m_name);
	}

	vft_hook::vft_hook(vft_hook&& other) noexcept :
	    m_name(std::move(other.m_name)),
	    m_slot(other.m_slot),
	    m_detour(other.m_detour),
	    m_original(other.m_original),
	    m_enabled(other.m_enabled)
	{
		other.m_slot = nullptr;
		other.m_detour = nullptr;
		other.m_original = nullptr;
		other.m_enabled = false;
	}

	vft_hook& vft_hook::operator=(vft_hook&& other) noexcept
	{
		if (this != &other)
		{
			if (m_enabled)
			{
				disable();
			}

			m_name = std::move(other.m_name);
			m_slot = other.m_slot;
			m_detour = other.m_detour;
			m_original = other.m_original;
			m_enabled = other.m_enabled;

			other.m_slot = nullptr;
			other.m_detour = nullptr;
			other.m_original = nullptr;
			other.m_enabled = false;
		}
		return *this;
	}

	bool vft_hook::enable()
	{
		if (m_enabled || !m_slot)
			return true;

		DWORD old_protect{};
		if (!VirtualProtect(m_slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect))
		{
			throw std::runtime_error(std::format("VirtualProtect failed while enabling vft_hook '{}'", m_name));
		}

		*m_slot = m_detour;
		VirtualProtect(m_slot, sizeof(void*), old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_slot, sizeof(void*));

		m_enabled = true;
		return true;
	}

	bool vft_hook::disable()
	{
		if (!m_enabled || !m_slot)
			return true;

		DWORD old_protect{};
		if (!VirtualProtect(m_slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect))
		{
			return false;
		}

		*m_slot = m_original;
		VirtualProtect(m_slot, sizeof(void*), old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_slot, sizeof(void*));

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
