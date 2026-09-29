#include "ellohim/hooking/swap_pointer_hook.hpp"
#include "ellohim/logger.hpp"
#include "core/pointer_patch.hpp"

namespace ellohim
{
	swap_pointer_hook::swap_pointer_hook(std::string_view name, void** target, void* swap) :
	    m_name(name),
	    m_target(target),
	    m_swap(swap)
	{
		if (!swap || !core::read_pointer(target, m_original))
			throw std::invalid_argument("Invalid or unaligned pointer hook target/callback");
		m_writable = core::pointer_is_writable(target);
		logger::info("Created swap_pointer_hook '{}' for target at {:p}", m_name, static_cast<void*>(m_target));
	}
	swap_pointer_hook::swap_pointer_hook(std::string_view name, std::atomic<void*>& target, void* swap) :
	    m_name(name), m_atomic_target(&target), m_swap(swap), m_original(target.load())
	{
		static_assert(std::atomic<void*>::is_always_lock_free);
		if (!swap) throw std::invalid_argument("Null pointer hook callback");
	}
	bool swap_pointer_hook::exchange(void* expected, void* replacement) noexcept
	{
		if (m_atomic_target) return m_atomic_target->compare_exchange_strong(expected, replacement);
		return core::exchange_pointer(m_target, expected, replacement, m_writable);
	}

	swap_pointer_hook::~swap_pointer_hook() noexcept
	{
		if (m_enabled)
		{
			try { disable(); } catch (...) { /* Keep the external slot intact on conflict. */ }
		}
	}

	void swap_pointer_hook::enable()
	{
		if (m_enabled)
			return;

		if (!exchange(m_original, m_swap))
			throw std::runtime_error("Pointer hook enable failed or slot changed");

		m_enabled = true;
	}

	void swap_pointer_hook::disable()
	{
		if (!m_enabled)
			return;

		if (!exchange(m_swap, m_original))
			throw std::runtime_error("Pointer hook disable failed or slot changed");

		m_enabled = false;
	}
}
