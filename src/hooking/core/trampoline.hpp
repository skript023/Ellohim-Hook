#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>
namespace ellohim::core
{
	struct hook_info
	{
		void* target{};
		void* detour{};
		void* slot{};
		void* trampoline{};
		void* relay{};
		uint8_t original_bytes[32]{};
		uint8_t patch_bytes[32]{};
		uint32_t patch_size{};
		uint32_t stolen_size{};
		uint32_t trampoline_size{};
		uint32_t count{};
		uint8_t old_offsets[32]{};
		uint16_t new_offsets[32]{};
	};
	bool create_trampoline(void* target, void* detour, void* slot, hook_info& info);
}
