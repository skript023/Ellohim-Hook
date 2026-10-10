#include "ellohim/hooking/vmt_hook.hpp"
#include <algorithm>

namespace ellohim
{
	vmt_hook::vmt_hook(const std::string_view name, void* obj, std::size_t num_funcs) :
	    m_object(static_cast<void***>(obj)),
	    m_num_funcs(num_funcs + 1),
	    m_original_table(*m_object),
	    m_new_table(std::make_unique<void*[]>(m_num_funcs))
	{
		std::copy_n(m_original_table - 1, m_num_funcs, m_new_table.get());
	}

	vmt_hook::vmt_hook(void* obj, std::size_t num_funcs) :
	    vmt_hook("", obj, num_funcs)
	{
	}

	vmt_hook::~vmt_hook() noexcept
	{
		disable();
	}

	void vmt_hook::hook(std::size_t index, void* func)
	{
		if (index >= num_funcs())
			throw std::out_of_range("VMT hook index out of range");
		m_new_table[index + 1] = func;
	}

	void vmt_hook::unhook(std::size_t index)
	{
		if (index >= num_funcs())
			throw std::out_of_range("VMT unhook index out of range");
		m_new_table[index + 1] = m_original_table[index];
	}

	bool vmt_hook::enable()
	{
		*m_object = m_new_table.get() + 1;
		m_is_enabled = true;
		return true;
	}

	bool vmt_hook::disable()
	{
		*m_object = m_original_table;
		m_is_enabled = false;
		return true;
	}
}
