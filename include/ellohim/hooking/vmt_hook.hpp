#pragma once
#include "../common.hpp"

namespace ellohim
{
	class vmt_hook
	{
	public:
		explicit vmt_hook(void* obj, std::size_t num_funcs = 0);
		~vmt_hook() noexcept;

		vmt_hook(vmt_hook&& other) noexcept;
		vmt_hook& operator=(vmt_hook&& other) noexcept;

		vmt_hook(const vmt_hook&) = delete;
		vmt_hook& operator=(const vmt_hook&) = delete;

		void hook(std::size_t index, void* func);
		void unhook(std::size_t index);

		template<typename T>
		[[nodiscard]] T get_original(std::size_t index) const
		{
			if (!m_original_table)
				return nullptr;
			return reinterpret_cast<T>(m_original_table[index]);
		}

		void enable();
		void disable();

		[[nodiscard]] bool is_enabled() const noexcept
		{
			return m_is_enabled;
		}

		[[nodiscard]] std::size_t num_funcs() const noexcept
		{
			return m_num_funcs > 0 ? m_num_funcs - 1 : 0;
		}

	private:
		void*** m_object{nullptr};
		std::size_t m_num_funcs{0}; // includes RTTI entry (num_funcs + 1)

		void** m_original_table{nullptr};
		std::unique_ptr<void*[]> m_new_table;
		bool m_is_enabled{false};

		static std::size_t count_virtual_functions(void** table);
	};
}
