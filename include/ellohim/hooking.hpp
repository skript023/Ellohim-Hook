#pragma once
#include "common.hpp"
#include "memory/handle.hpp"
#include "memory/range.hpp"
#include "memory/module.hpp"
#include "memory/pattern.hpp"
#include "hooking/detour_base.hpp"
#include "hooking/detour_hook.hpp"
#include "hooking/vmt_hook.hpp"
#include "hooking/vft_hook.hpp"
#include "hooking/iat_hook.hpp"
#include "hooking/swap_pointer_hook.hpp"
#include "hooking/mid_hook.hpp"

namespace ellohim
{
	struct minhook_keepalive
	{
		minhook_keepalive();
		~minhook_keepalive();
	};

	class hooking
	{
	public:
		explicit hooking();
		virtual ~hooking();

		virtual void enable();
		virtual void disable();

		[[nodiscard]] bool is_enabled() const noexcept
		{
			return m_enabled;
		}

	protected:
		minhook_keepalive m_minhook;
		bool m_enabled{false};
	};

	inline hooking* g_hooking{nullptr};
}

// Seamless compatibility with BigBase / Mono Hacking codebase style
namespace big
{
	using namespace ellohim;
}
