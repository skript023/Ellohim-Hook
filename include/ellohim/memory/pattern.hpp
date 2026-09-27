#pragma once
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>
#include "handle.hpp"

namespace memory
{
	class range;

	class pattern
	{
		friend class range;

	public:
		pattern(std::string_view ida_sig);
		explicit pattern(const void* bytes, std::string_view mask);

		inline pattern(const char* ida_sig) :
		    pattern(std::string_view(ida_sig))
		{
		}

		[[nodiscard]] const std::vector<std::optional<std::uint8_t>>& bytes() const noexcept
		{
			return m_bytes;
		}

		[[nodiscard]] std::size_t size() const noexcept
		{
			return m_bytes.size();
		}

	private:
		std::vector<std::optional<std::uint8_t>> m_bytes;
	};
}
