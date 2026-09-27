#include "ellohim/memory/module.hpp"

namespace memory
{
	module::module(HMODULE mod) : range(mod, 0)
	{
		if (!mod)
			return;

		__try
		{
			auto dos_header = m_base.as<IMAGE_DOS_HEADER*>();
			if (dos_header && dos_header->e_magic == IMAGE_DOS_SIGNATURE)
			{
				auto nt_header = m_base.add(dos_header->e_lfanew).as<IMAGE_NT_HEADERS*>();
				if (nt_header && nt_header->Signature == IMAGE_NT_SIGNATURE)
				{
					m_size = nt_header->OptionalHeader.SizeOfImage;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			m_size = 0;
		}
	}

	module::module(std::nullptr_t) : module(GetModuleHandleW(nullptr))
	{
	}

	module::module(std::string_view name) : module([](std::string_view n) -> HMODULE {
		std::string name_str(n);
		HMODULE mod = GetModuleHandleA(name_str.c_str());
		if (!mod)
		{
			mod = LoadLibraryA(name_str.c_str());
		}
		return mod;
	}(name))
	{
	}

	module::module(std::wstring_view name) : module([](std::wstring_view n) -> HMODULE {
		std::wstring name_str(n);
		HMODULE mod = GetModuleHandleW(name_str.c_str());
		if (!mod)
		{
			mod = LoadLibraryW(name_str.c_str());
		}
		return mod;
	}(name))
	{
	}

	handle module::get_export(std::string_view symbol_name) const
	{
		if (!m_base)
			return handle();

		std::string sym_str(symbol_name);
		return GetProcAddress(m_base.as<HMODULE>(), sym_str.c_str());
	}
}
