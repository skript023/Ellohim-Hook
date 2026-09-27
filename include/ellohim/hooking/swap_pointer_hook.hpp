#pragma once
#include "../common.hpp"

namespace ellohim
{
	class swap_pointer_hook
	{
	public:
		explicit swap_pointer_hook(std::string_view name, void** target, void* swap);
		~swap_pointer_hook() noexcept;

		void enable();
		void disable();

		[[nodiscard]] bool is_enabled() const noexcept { return m_enabled; }
		[[nodiscard]] std::string_view name() const noexcept { return m_name; }

		template<typename T>
		[[nodiscard]] T get_original() const noexcept
		{
			return reinterpret_cast<T>(m_original);
		}

	private:
		std::string m_name;
		void** m_target{nullptr};
		void* m_swap{nullptr};
		void* m_original{nullptr};
		bool m_enabled{false};
	};
}
