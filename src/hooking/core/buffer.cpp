#include "buffer.hpp"
#include <mutex>
#include <vector>

namespace ellohim::core
{
	constexpr std::size_t MEMORY_BLOCK_SIZE = 0x1000;
	constexpr uintptr_t MAX_MEMORY_RANGE = 0x40000000; // 1024 MB

	struct memory_slot
	{
		union
		{
			memory_slot* next;
			uint8_t buffer[MEMORY_SLOT_SIZE];
		};
	};

	struct memory_block
	{
		memory_block* next{nullptr};
		memory_slot* free_slots{nullptr};
		std::size_t used_count{0};
	};

	static std::recursive_mutex g_buffer_mutex;
	static memory_block* g_memory_blocks{nullptr};

#if defined(_M_X64) || defined(__x86_64__)
	static void* find_prev_free_region(void* address, void* min_addr, DWORD allocation_granularity)
	{
		auto try_addr = reinterpret_cast<uintptr_t>(address);
		try_addr -= try_addr % allocation_granularity;
		try_addr -= allocation_granularity;

		while (try_addr >= reinterpret_cast<uintptr_t>(min_addr))
		{
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQuery(reinterpret_cast<void*>(try_addr), &mbi, sizeof(mbi)) == 0)
				break;

			if (mbi.State == MEM_FREE)
				return reinterpret_cast<void*>(try_addr);

			if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < allocation_granularity)
				break;

			try_addr = reinterpret_cast<uintptr_t>(mbi.AllocationBase) - allocation_granularity;
		}

		return nullptr;
	}

	static void* find_next_free_region(void* address, void* max_addr, DWORD allocation_granularity)
	{
		auto try_addr = reinterpret_cast<uintptr_t>(address);
		try_addr -= try_addr % allocation_granularity;
		try_addr += allocation_granularity;

		while (try_addr <= reinterpret_cast<uintptr_t>(max_addr))
		{
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQuery(reinterpret_cast<void*>(try_addr), &mbi, sizeof(mbi)) == 0)
				break;

			if (mbi.State == MEM_FREE)
				return reinterpret_cast<void*>(try_addr);

			try_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
			try_addr += allocation_granularity - 1;
			try_addr -= try_addr % allocation_granularity;
		}

		return nullptr;
	}
#endif

	void* allocate_page_near(void* origin, std::size_t size)
	{
		std::lock_guard lock(g_buffer_mutex);

		SYSTEM_INFO si{};
		GetSystemInfo(&si);

		std::size_t page_size = si.dwPageSize;
		std::size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

#if defined(_M_X64) || defined(__x86_64__)
		auto min_addr = reinterpret_cast<uintptr_t>(origin) > MAX_MEMORY_RANGE ?
		    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(origin) - MAX_MEMORY_RANGE) :
		    si.lpMinimumApplicationAddress;

		auto max_addr = (UINTPTR_MAX - reinterpret_cast<uintptr_t>(origin) > MAX_MEMORY_RANGE) ?
		    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(origin) + MAX_MEMORY_RANGE) :
		    si.lpMaximumApplicationAddress;

		if (min_addr < si.lpMinimumApplicationAddress) min_addr = si.lpMinimumApplicationAddress;
		if (max_addr > si.lpMaximumApplicationAddress) max_addr = si.lpMaximumApplicationAddress;

		void* alloc_addr = nullptr;
		for (int i = 0; i < 2 && !alloc_addr; ++i)
		{
			if (i == 0)
				alloc_addr = find_prev_free_region(origin, min_addr, si.dwAllocationGranularity);
			else
				alloc_addr = find_next_free_region(origin, max_addr, si.dwAllocationGranularity);

			while (alloc_addr)
			{
				void* mem = VirtualAlloc(alloc_addr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (mem)
					return mem;

				if (i == 0)
					alloc_addr = find_prev_free_region(alloc_addr, min_addr, si.dwAllocationGranularity);
				else
					alloc_addr = find_next_free_region(alloc_addr, max_addr, si.dwAllocationGranularity);
			}
		}

		return nullptr;
#else
		return VirtualAlloc(nullptr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
	}

	void free_page_near(void* ptr, std::size_t)
	{
		if (ptr)
		{
			VirtualFree(ptr, 0, MEM_RELEASE);
		}
	}

	static memory_block* get_memory_block(void* origin)
	{
		for (auto* block = g_memory_blocks; block != nullptr; block = block->next)
		{
			if (block->free_slots != nullptr)
			{
#if defined(_M_X64) || defined(__x86_64__)
				auto diff = std::abs(reinterpret_cast<intptr_t>(origin) - reinterpret_cast<intptr_t>(block));
				if (static_cast<uintptr_t>(diff) < MAX_MEMORY_RANGE)
					return block;
#else
				return block;
#endif
			}
		}

		void* alloc_addr = allocate_page_near(origin, MEMORY_BLOCK_SIZE);
		if (!alloc_addr)
			return nullptr;

		auto* new_block = static_cast<memory_block*>(alloc_addr);
		new_block->next = g_memory_blocks;
		new_block->free_slots = nullptr;
		new_block->used_count = 0;

		auto* slot = reinterpret_cast<memory_slot*>(reinterpret_cast<uintptr_t>(alloc_addr) + sizeof(memory_block));
		auto* end = reinterpret_cast<memory_slot*>(reinterpret_cast<uintptr_t>(alloc_addr) + MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

		while (slot <= end)
		{
			slot->next = new_block->free_slots;
			new_block->free_slots = slot;
			slot = reinterpret_cast<memory_slot*>(reinterpret_cast<uintptr_t>(slot) + MEMORY_SLOT_SIZE);
		}

		g_memory_blocks = new_block;
		return new_block;
	}

	void* allocate_slot(void* origin)
	{
		std::lock_guard lock(g_buffer_mutex);
		auto* block = get_memory_block(origin);
		if (!block || !block->free_slots)
			return nullptr;

		auto* slot = block->free_slots;
		block->free_slots = slot->next;
		block->used_count++;
		return slot;
	}

	void free_slot(void* slot)
	{
		if (!slot)
			return;

		std::lock_guard lock(g_buffer_mutex);
		auto* target_slot = static_cast<memory_slot*>(slot);

		for (auto* block = g_memory_blocks; block != nullptr; block = block->next)
		{
			auto block_start = reinterpret_cast<uintptr_t>(block);
			auto block_end = block_start + MEMORY_BLOCK_SIZE;
			auto slot_addr = reinterpret_cast<uintptr_t>(target_slot);

			if (slot_addr >= block_start && slot_addr < block_end)
			{
				target_slot->next = block->free_slots;
				block->free_slots = target_slot;
				block->used_count--;
				return;
			}
		}
	}

	void cleanup_buffers()
	{
		std::lock_guard lock(g_buffer_mutex);
		auto* block = g_memory_blocks;
		g_memory_blocks = nullptr;

		while (block)
		{
			auto* next = block->next;
			VirtualFree(block, 0, MEM_RELEASE);
			block = next;
		}
	}
}
