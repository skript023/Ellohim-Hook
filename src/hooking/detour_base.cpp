#include "ellohim/hooking/detour_base.hpp"
#include <algorithm>

namespace ellohim
{
	detour_base::detour_base(std::string_view name) :
	    m_name(name),
	    m_enabled(false)
	{
		m_detour_bases.emplace_back(this);
	}

	detour_base::~detour_base()
	{
		if (m_clear_binding)
		{
			m_clear_binding(this);
		}
		std::erase(m_detour_bases, this);
	}

	std::vector<detour_base*>& detour_base::hooks()
	{
		return m_detour_bases;
	}

	bool detour_base::enable_all()
	{
		bool status = true;
		for (auto* hook : m_detour_bases)
		{
			status = hook->enable() && status;
		}
		return status;
	}

	bool detour_base::disable_all()
	{
		bool status = true;
		for (auto* hook : m_detour_bases)
		{
			status = hook->disable() && status;
		}
		return status;
	}
}
