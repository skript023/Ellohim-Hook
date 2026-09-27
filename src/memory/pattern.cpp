#include "ellohim/memory/pattern.hpp"

namespace memory
{
	pattern::pattern(std::string_view ida_sig)
	{
		auto to_upper = [](char c) -> char {
			return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
		};

		auto to_hex = [&](char c) -> std::optional<std::uint8_t> {
			c = to_upper(c);
			if (c >= '0' && c <= '9')
				return static_cast<std::uint8_t>(c - '0');
			if (c >= 'A' && c <= 'F')
				return static_cast<std::uint8_t>(10 + (c - 'A'));
			return std::nullopt;
		};

		for (std::size_t i = 0; i < ida_sig.size(); ++i)
		{
			if (ida_sig[i] == ' ')
				continue;

			if (ida_sig[i] == '?')
			{
				m_bytes.push_back(std::nullopt);
				if (i + 1 < ida_sig.size() && ida_sig[i + 1] == '?')
				{
					++i;
				}
			}
			else
			{
				if (i + 1 < ida_sig.size())
				{
					auto c1 = to_hex(ida_sig[i]);
					auto c2 = to_hex(ida_sig[i + 1]);

					if (c1 && c2)
					{
						m_bytes.emplace_back(static_cast<std::uint8_t>((*c1 << 4) | *c2));
						++i;
					}
				}
			}
		}
	}

	pattern::pattern(const void* bytes, std::string_view mask)
	{
		const auto* byte_ptr = static_cast<const std::uint8_t*>(bytes);
		for (std::size_t i = 0; i < mask.size(); ++i)
		{
			if (mask[i] != '?')
				m_bytes.emplace_back(byte_ptr[i]);
			else
				m_bytes.push_back(std::nullopt);
		}
	}
}
