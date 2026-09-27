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
		g_hooking = this;
	}

	hooking::~hooking()
	{
		if (m_enabled)
		{
			disable();
		}

		while (!detour_base::hooks().empty())
		{
			delete detour_base::hooks().back();
		}

		g_hooking = nullptr;
	}

	void hooking::enable()
	{
		detour_base::enable_all();
		m_enabled = true;
		logger::info("All hooks enabled");
	}

	void hooking::disable()
	{
		m_enabled = false;
		detour_base::disable_all();
		logger::info("All hooks disabled");
	}
}
