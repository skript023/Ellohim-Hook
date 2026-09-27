#include "ellohim/memory/range.hpp"
#include "ellohim/memory/pattern.hpp"
#include <algorithm>

namespace memory
{
	range::range(handle base, std::size_t size) noexcept :
	    m_base(base),
	    m_size(size)
	{
	}

	handle range::begin() const noexcept
	{
		return m_base;
	}

	handle range::end() const noexcept
	{
		return m_base.add(m_size);
	}

	std::size_t range::size() const noexcept
	{
		return m_size;
	}

	bool range::contains(handle h) const noexcept
	{
		auto addr = h.as<std::uintptr_t>();
		return addr >= begin().as<std::uintptr_t>() && addr < end().as<std::uintptr_t>();
	}

	handle range::scan(const pattern& sig) const
	{
		const auto& bytes = sig.bytes();
		if (bytes.empty() || m_size < bytes.size() || !m_base)
			return handle();

		const auto* data = m_base.as<const std::uint8_t*>();
		const std::size_t scan_len = m_size - bytes.size();

		for (std::size_t i = 0; i <= scan_len; ++i)
		{
			bool match = true;
			for (std::size_t j = 0; j < bytes.size(); ++j)
			{
				if (bytes[j].has_value() && data[i + j] != bytes[j].value())
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				return m_base.add(i);
			}
		}

		return handle();
	}

	std::vector<handle> range::scan_all(const pattern& sig) const
	{
		std::vector<handle> results;
		const auto& bytes = sig.bytes();
		if (bytes.empty() || m_size < bytes.size() || !m_base)
			return results;

		const auto* data = m_base.as<const std::uint8_t*>();
		const std::size_t scan_len = m_size - bytes.size();

		for (std::size_t i = 0; i <= scan_len; ++i)
		{
			bool match = true;
			for (std::size_t j = 0; j < bytes.size(); ++j)
			{
				if (bytes[j].has_value() && data[i + j] != bytes[j].value())
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				results.push_back(m_base.add(i));
			}
		}

		return results;
	}
}
