#include "ellohim/hooking.hpp"
#include "ellohim/logger.hpp"
#include "core/buffer.hpp"

namespace ellohim
{
	minhook_keepalive::minhook_keepalive()
	{
		// Native environment initialization (no external minhook needed)
		logger::info("Ellohim-Hook native hooking engine initialized");
	}

	minhook_keepalive::~minhook_keepalive()
	{
		core::cleanup_buffers();
		logger::info("Ellohim-Hook native hooking engine uninitialized");
	}

	hooking::hooking() :
	    m_enabled(false)
	{
		if (g_hooking) throw std::logic_error("Only one hook manager may exist");
		g_hooking = this;
	}

	hooking::~hooking()
	{
		// Failed hooks retain their objects and callback bindings for an explicit retry.
		mid_hook::destroy_owned();
		detour_base::destroy_owned();

		g_hooking = nullptr;
	}

	void hooking::enable()
	{
		std::vector<detour_base*> inactive_detours;
		std::vector<mid_hook*> inactive_mids;
		for (auto* hook : detour_base::hooks()) if (!hook->is_enabled()) inactive_detours.push_back(hook);
		for (auto* hook : mid_hook::hooks()) if (!hook->is_enabled()) inactive_mids.push_back(hook);
		try
		{
			if (!detour_base::enable_all()) throw std::runtime_error("Could not enable all detours");
			if (!mid_hook::enable_all()) throw std::runtime_error("Could not enable all mid-hooks");
		}
		catch (...)
		{
			bool restored = true;
			for (auto it = inactive_mids.rbegin(); it != inactive_mids.rend(); ++it)
				restored = (*it)->disable() && restored;
			for (auto it = inactive_detours.rbegin(); it != inactive_detours.rend(); ++it)
			{
				try { restored = (*it)->disable() && restored; }
				catch (...) { restored = false; }
			}
			m_enabled = detour_base::any_enabled() || mid_hook::any_enabled();
			if (!restored) throw std::runtime_error("Manager rollback failed; hooks remain active");
			throw;
		}
		m_enabled = detour_base::any_enabled() || mid_hook::any_enabled();
		logger::info("All hooks enabled");
	}

	void hooking::disable()
	{
		const bool mids_disabled = mid_hook::disable_all();
		const bool detours_disabled = detour_base::disable_all();
		m_enabled = detour_base::any_enabled() || mid_hook::any_enabled();
		if (!mids_disabled || !detours_disabled) throw std::runtime_error("Some hooks remain enabled");
		logger::info("All hooks disabled");
	}
}
