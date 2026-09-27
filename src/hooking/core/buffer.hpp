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
#if defined(_M_X64) || defined(__x86_64__)
	constexpr std::size_t MEMORY_SLOT_SIZE = 64;
#else
	constexpr std::size_t MEMORY_SLOT_SIZE = 32;
#endif

	void* allocate_slot(void* origin);
	void free_slot(void* slot);

	void* allocate_page_near(void* origin, std::size_t size);
	void free_page_near(void* ptr, std::size_t size);

	void cleanup_buffers();
}
