#pragma once
#include "../common.hpp"

namespace ellohim
{
	class vmt_hook
	{
	public:
		explicit vmt_hook(const std::string_view name, void* obj, std::size_t num_funcs);
		explicit vmt_hook(void* obj, std::size_t num_funcs);
		~vmt_hook() noexcept;

		vmt_hook(vmt_hook&& that) = delete;
		vmt_hook& operator=(vmt_hook&& that) = delete;
		vmt_hook(vmt_hook const&) = delete;
		vmt_hook& operator=(vmt_hook const&) = delete;

		void hook(std::size_t index, void* func);
		void unhook(std::size_t index);

		template<typename T>
		T get_original(std::size_t index);

		bool enable();
		bool disable();

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
		std::size_t m_num_funcs{0};

		void** m_original_table{nullptr};
		std::unique_ptr<void*[]> m_new_table;
		bool m_is_enabled{false};
	};

	template<typename T>
	inline T vmt_hook::get_original(std::size_t index)
	{
		return reinterpret_cast<T>(m_original_table[index]);
	}
}
