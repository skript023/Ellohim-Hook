#pragma once
#include <string_view>
#include <string>
#include "range.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace memory
{
	class module : public range
	{
	public:
		module(HMODULE mod);
		explicit module(std::nullptr_t);
		explicit module(std::string_view name);
		explicit module(std::wstring_view name);

		[[nodiscard]] handle get_export(std::string_view symbol_name) const;

		[[nodiscard]] HMODULE handle_instance() const noexcept
		{
			return m_base.as<HMODULE>();
		}
	};
}
