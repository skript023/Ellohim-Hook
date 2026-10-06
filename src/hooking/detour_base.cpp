#include "ellohim/hooking/detour_base.hpp"
#include <algorithm>

namespace ellohim
{
	detour_base::detour_base(std::string_view name, bool register_hook) :
	    m_name(name),
	    m_enabled(false)
	{
		if (register_hook)
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
		std::vector<detour_base*> activated;
		activated.reserve(m_detour_bases.size());
		auto rollback = [&] {
			bool restored = true;
			for (auto it = activated.rbegin(); it != activated.rend(); ++it)
			{
				try { restored = (*it)->disable() && restored; }
				catch (...) { restored = false; }
			}
			activated.clear();
			return restored;
		};
		try
		{
			for (auto* hook : m_detour_bases)
			{
				if (hook->is_enabled()) continue;
				activated.push_back(hook);
				if (!hook->enable())
				{
					if (!rollback()) throw std::runtime_error("Hook batch rollback failed");
					return false;
				}
			}
		}
		catch (...)
		{
			if (!rollback()) throw std::runtime_error("Hook batch rollback failed");
			throw;
		}
		return true;
	}

	bool detour_base::disable_all()
	{
		bool status = true;
		for (auto it = m_detour_bases.rbegin(); it != m_detour_bases.rend(); ++it)
		{
			try { status = (*it)->disable() && status; }
			catch (...) { status = false; }
		}
		return status;
	}
	bool detour_base::any_enabled()
	{
		return std::any_of(m_detour_bases.begin(), m_detour_bases.end(), [](auto* hook) { return hook->is_enabled(); });
	}
	bool detour_base::destroy_owned()
	{
		bool status = true;
		for (size_t i = m_detour_bases.size(); i > 0; --i)
		{
			auto* hook = m_detour_bases[i - 1];
			if (!hook->m_registry_owned) continue;
			try { if (!hook->disable()) { status = false; continue; } }
			catch (...) { status = false; continue; }
			delete hook;
		}
		return status;
	}
}
