#include "ellohim/hooking/iat_hook.hpp"
#include "ellohim/logger.hpp"
#include "core/pointer_patch.hpp"
#include <cstring>

namespace ellohim
{
	static bool in_image(size_t offset, size_t length, size_t size)
	{
		return offset <= size && length <= size - offset;
	}
	static void** find_import(HMODULE module, const char* dll, const char* function) noexcept
	{
		__try
		{
			auto* base = reinterpret_cast<uint8_t*>(module);
			if (!base) return nullptr;
			auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > 0x100000) return nullptr;
			auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
			    nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
			    nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return nullptr;
			const size_t size = nt->OptionalHeader.SizeOfImage;
			if (!in_image(dos->e_lfanew, sizeof(*nt), size)) return nullptr;
			const auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			if (!dir.VirtualAddress || !in_image(dir.VirtualAddress, dir.Size, size)) return nullptr;
			const auto count = dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
			auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
			for (size_t i = 0; i < count; ++i)
			{
				const auto& desc = descriptors[i];
				if (!desc.Name) break;
				if (!in_image(desc.Name, 1, size) || !std::memchr(base + desc.Name, 0, size - desc.Name)) return nullptr;
				if (_stricmp(reinterpret_cast<char*>(base + desc.Name), dll)) continue;
				// A loaded FirstThunk contains function addresses, not import-name RVAs.
				if (!desc.OriginalFirstThunk || !desc.FirstThunk) return nullptr;
				for (size_t index = 0; index < size / sizeof(IMAGE_THUNK_DATA64); ++index)
				{
					const size_t names = size_t(desc.OriginalFirstThunk) + index * sizeof(IMAGE_THUNK_DATA64);
					const size_t slots = size_t(desc.FirstThunk) + index * sizeof(IMAGE_THUNK_DATA64);
					if (!in_image(names, sizeof(IMAGE_THUNK_DATA64), size) || !in_image(slots, sizeof(IMAGE_THUNK_DATA64), size)) return nullptr;
					const auto address = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + names)->u1.AddressOfData;
					if (!address) break;
					if (IMAGE_SNAP_BY_ORDINAL64(address)) continue;
					if (!in_image(address, sizeof(WORD) + 1, size)) return nullptr;
					const auto name_offset = size_t(address) + sizeof(WORD);
					const auto* name = reinterpret_cast<const char*>(base + name_offset);
					if (!std::memchr(name, 0, size - name_offset)) return nullptr;
					if (!std::strcmp(name, function)) return reinterpret_cast<void**>(base + slots);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		return nullptr;
	}

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

		std::string dll_name_str(target_dll), func_name_str(function_name);
		m_iat_slot = find_import(module_to_hook, dll_name_str.c_str(), func_name_str.c_str());
		if (m_iat_slot && core::read_pointer(m_iat_slot, m_original))
		{
			m_writable = core::pointer_is_writable(m_iat_slot);
			return;
		}

		throw std::runtime_error(std::format("Failed to find import {}!{} for iat_hook '{}'", target_dll, function_name, m_name));
	}

	iat_hook::~iat_hook() noexcept
	{
		if (m_clear_binding) m_clear_binding(this);
		std::erase(m_iat_hooks, this);
		if (m_enabled)
		{
			disable();
		}
		logger::info("Removed iat_hook '{}'", m_name);
	}

	bool iat_hook::enable()
	{
		if (m_enabled || !m_iat_slot)
			return true;

		if (!core::exchange_pointer(m_iat_slot, m_original, m_detour, m_writable))
			return false;

		m_enabled = true;
		return true;
	}

	bool iat_hook::disable()
	{
		if (!m_enabled || !m_iat_slot)
			return true;

		if (!core::exchange_pointer(m_iat_slot, m_detour, m_original, m_writable))
			return false;

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
