#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace ellohim::core
{
	struct hook_info
	{
		void* target{nullptr};
		void* detour{nullptr};
		void* slot{nullptr};
		void* trampoline{nullptr};
		void* relay{nullptr};
		uint8_t original_bytes[32]{};
		uint8_t patch_bytes[8]{};
		uint32_t patch_size{0};
		uint32_t stolen_size{0};
	};

	bool create_trampoline(void* target, void* detour, void* slot, hook_info& out_info);
}
