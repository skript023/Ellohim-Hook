#pragma once
#include "../common.hpp"
#include <atomic>

namespace ellohim
{
	class swap_pointer_hook
	{
	public:
		explicit swap_pointer_hook(std::string_view name, void** target, void* swap);
		// Preferred for application-owned dispatch slots: no WinAPI on this path.
		explicit swap_pointer_hook(std::string_view name, std::atomic<void*>& target, void* swap);
		~swap_pointer_hook() noexcept;
		swap_pointer_hook(const swap_pointer_hook&) = delete;
		swap_pointer_hook& operator=(const swap_pointer_hook&) = delete;

		void enable();
		void disable();
		// All concurrent C++ readers of a void** slot must use atomic access too.
		[[nodiscard]] static void* load_target(void** target)
		{
			if (!target || reinterpret_cast<uintptr_t>(target) % std::atomic_ref<void*>::required_alignment)
				throw std::invalid_argument("Invalid pointer slot alignment");
			return std::atomic_ref<void*>(*target).load();
		}

		[[nodiscard]] bool is_enabled() const noexcept
		{
			return m_enabled;
		}
		[[nodiscard]] std::string_view name() const noexcept
		{
			return m_name;
		}

		template<typename T>
		[[nodiscard]] T get_original() const noexcept
		{
			return reinterpret_cast<T>(m_original);
		}

	private:
		std::string m_name;
		void** m_target{nullptr};
		std::atomic<void*>* m_atomic_target{nullptr};
		bool m_writable{false};
		void* m_swap{nullptr};
		void* m_original{nullptr};
		bool m_enabled{false};
		bool exchange(void* expected, void* replacement) noexcept;
	};
}
