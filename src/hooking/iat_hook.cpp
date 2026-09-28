#include "ellohim/hooking/iat_hook.hpp"
#include "ellohim/logger.hpp"

namespace ellohim
{
	iat_hook::iat_hook(std::string_view name, HMODULE module_to_hook, std::string_view target_dll, std::string_view function_name, void* detour) :
	    m_name(name),
	    m_detour(detour)
	{
		if (!module_to_hook)
		{
			module_to_hook = GetModuleHandleW(nullptr);
		}
		if (!m_detour)
		{
			throw std::runtime_error(std::format("Failed to create iat_hook '{}': detour pointer is null", m_name));
		}

		auto base = reinterpret_cast<uintptr_t>(module_to_hook);
		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			throw std::runtime_error(std::format("Invalid DOS signature in module for iat_hook '{}'", m_name));
		}

		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		{
			throw std::runtime_error(std::format("Invalid NT signature in module for iat_hook '{}'", m_name));
		}

		const auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!import_dir.VirtualAddress || !import_dir.Size)
		{
			throw std::runtime_error(std::format("Import directory not found for iat_hook '{}'", m_name));
		}

		std::string dll_name_str(target_dll);
		std::string func_name_str(function_name);

		auto* import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_dir.VirtualAddress);
		while (import_desc->Name)
		{
			auto* current_dll_name = reinterpret_cast<const char*>(base + import_desc->Name);
			if (_stricmp(current_dll_name, dll_name_str.c_str()) == 0)
			{
				auto* orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + (import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk));
				auto* iat_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);

				while (orig_thunk->u1.AddressOfData)
				{
					if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
					{
						auto* import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + orig_thunk->u1.AddressOfData);
						if (strcmp(import_by_name->Name, func_name_str.c_str()) == 0)
						{
							m_iat_slot = reinterpret_cast<void**>(&iat_thunk->u1.Function);
							m_original = *m_iat_slot;
							logger::info("Created iat_hook '{}' for {}!{} at slot {:p}", m_name, target_dll, function_name, static_cast<void*>(m_iat_slot));
							return;
						}
					}
					++orig_thunk;
					++iat_thunk;
				}
			}
			++import_desc;
		}

		throw std::runtime_error(std::format("Failed to find import {}!{} for iat_hook '{}'", target_dll, function_name, m_name));
	}

	iat_hook::~iat_hook() noexcept
	{
		if (m_enabled)
		{
			disable();
		}
		logger::info("Removed iat_hook '{}'", m_name);
	}

	iat_hook::iat_hook(iat_hook&& other) noexcept :
	    m_name(std::move(other.m_name)),
	    m_iat_slot(other.m_iat_slot),
	    m_detour(other.m_detour),
	    m_original(other.m_original),
	    m_enabled(other.m_enabled)
	{
		other.m_iat_slot = nullptr;
		other.m_detour = nullptr;
		other.m_original = nullptr;
		other.m_enabled = false;
	}

	iat_hook& iat_hook::operator=(iat_hook&& other) noexcept
	{
		if (this != &other)
		{
			if (m_enabled)
			{
				disable();
			}

			m_name = std::move(other.m_name);
			m_iat_slot = other.m_iat_slot;
			m_detour = other.m_detour;
			m_original = other.m_original;
			m_enabled = other.m_enabled;

			other.m_iat_slot = nullptr;
			other.m_detour = nullptr;
			other.m_original = nullptr;
			other.m_enabled = false;
		}
		return *this;
	}

	bool iat_hook::enable()
	{
		if (m_enabled || !m_iat_slot)
			return true;

		DWORD old_protect{};
		if (!VirtualProtect(m_iat_slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect))
		{
			throw std::runtime_error(std::format("VirtualProtect failed while enabling iat_hook '{}'", m_name));
		}

		*m_iat_slot = m_detour;
		VirtualProtect(m_iat_slot, sizeof(void*), old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_iat_slot, sizeof(void*));

		m_enabled = true;
		return true;
	}

	bool iat_hook::disable()
	{
		if (!m_enabled || !m_iat_slot)
			return true;

		DWORD old_protect{};
		if (!VirtualProtect(m_iat_slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old_protect))
		{
			return false;
		}

		*m_iat_slot = m_original;
		VirtualProtect(m_iat_slot, sizeof(void*), old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_iat_slot, sizeof(void*));

		m_enabled = false;
		return true;
	}

	bool iat_hook::enable_all()
	{
		bool success = true;
		for (auto* hook : m_iat_hooks)
		{
			if (!hook->enable())
				success = false;
		}
		return success;
	}

	bool iat_hook::disable_all()
	{
		bool success = true;
		for (auto* hook : m_iat_hooks)
		{
			if (!hook->disable())
				success = false;
		}
		return success;
	}
}
