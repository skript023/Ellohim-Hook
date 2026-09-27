#include "ellohim/hooking/vmt_hook.hpp"
#include "ellohim/logger.hpp"
#include <algorithm>

namespace ellohim
{
	std::size_t vmt_hook::count_virtual_functions(void** table)
	{
		if (!table)
			return 0;

		std::size_t count = 0;
		MEMORY_BASIC_INFORMATION mbi{};

		while (table[count] != nullptr)
		{
			if (VirtualQuery(table[count], &mbi, sizeof(mbi)) == 0)
				break;

			constexpr DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
			if ((mbi.State != MEM_COMMIT) || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) || !(mbi.Protect & exec_mask))
				break;

			++count;
		}

		return count;
	}

	vmt_hook::vmt_hook(void* obj, std::size_t num_funcs)
	{
		if (!obj)
		{
			throw std::runtime_error("Failed to initialize vmt_hook: object pointer is null");
		}

		m_object = static_cast<void***>(obj);
		m_original_table = *m_object;

		if (!m_original_table)
		{
			throw std::runtime_error("Failed to initialize vmt_hook: original virtual table is null");
		}

		if (num_funcs == 0)
		{
			num_funcs = count_virtual_functions(m_original_table);
		}

		m_num_funcs = num_funcs + 1;
		m_new_table = std::make_unique<void*[]>(m_num_funcs);

		// Copy RTTI Complete Object Locator pointer (index -1) and all function pointers
		std::copy_n(m_original_table - 1, m_num_funcs, m_new_table.get());

		logger::info("Created vmt_hook for object at {:p} ({} virtual functions)", obj, num_funcs);
	}

	vmt_hook::~vmt_hook() noexcept
	{
		if (m_is_enabled)
		{
			disable();
		}
	}

	vmt_hook::vmt_hook(vmt_hook&& other) noexcept :
	    m_object(other.m_object),
	    m_num_funcs(other.m_num_funcs),
	    m_original_table(other.m_original_table),
	    m_new_table(std::move(other.m_new_table)),
	    m_is_enabled(other.m_is_enabled)
	{
		other.m_object = nullptr;
		other.m_original_table = nullptr;
		other.m_num_funcs = 0;
		other.m_is_enabled = false;
	}

	vmt_hook& vmt_hook::operator=(vmt_hook&& other) noexcept
	{
		if (this != &other)
		{
			if (m_is_enabled)
			{
				disable();
			}

			m_object = other.m_object;
			m_num_funcs = other.m_num_funcs;
			m_original_table = other.m_original_table;
			m_new_table = std::move(other.m_new_table);
			m_is_enabled = other.m_is_enabled;

			other.m_object = nullptr;
			other.m_original_table = nullptr;
			other.m_num_funcs = 0;
			other.m_is_enabled = false;
		}
		return *this;
	}

	void vmt_hook::hook(std::size_t index, void* func)
	{
		if (index + 1 >= m_num_funcs)
		{
			throw std::out_of_range(std::format("vmt_hook::hook index {} out of range (max: {})", index, num_funcs() - 1));
		}
		m_new_table[index + 1] = func;
	}

	void vmt_hook::unhook(std::size_t index)
	{
		if (index + 1 >= m_num_funcs)
		{
			throw std::out_of_range(std::format("vmt_hook::unhook index {} out of range (max: {})", index, num_funcs() - 1));
		}
		m_new_table[index + 1] = m_original_table[index];
	}

	void vmt_hook::enable()
	{
		if (m_object && !m_is_enabled)
		{
			*m_object = m_new_table.get() + 1;
			m_is_enabled = true;
		}
	}

	void vmt_hook::disable()
	{
		if (m_object && m_is_enabled)
		{
			*m_object = m_original_table;
			m_is_enabled = false;
		}
	}
}
