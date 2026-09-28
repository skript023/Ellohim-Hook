#include "buffer.hpp"
#include <algorithm>
#include <limits>
#include <initializer_list>

namespace ellohim::core
{
	void* allocate_page_near(void* origin, std::size_t size)
	{
		SYSTEM_INFO info{};
		GetSystemInfo(&info);
		if (!origin || !size || size > SIZE_MAX - info.dwPageSize)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return nullptr;
		}
		size = (size + info.dwPageSize - 1) & ~(std::size_t(info.dwPageSize) - 1);
		const auto center = reinterpret_cast<uintptr_t>(origin);
		DWORD error = ERROR_NOT_ENOUGH_MEMORY;
		// A reachable entry jump does not guarantee that relocated RIP operands are reachable.
		// Prefer nearby pages before allowing allocations at the rel32 boundary.
		for (const uintptr_t reach : {uintptr_t{0x01000000}, uintptr_t{0x10000000}, uintptr_t{0x40000000}, uintptr_t{0x7fff0000}})
		{
			const auto low = std::max(reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress), center > reach ? center - reach : 0);
			const auto high = std::min(reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress), center + std::min(reach, UINTPTR_MAX - center));
			if (size > high - low)
			{
				continue;
			}
			using alloc2_t = PVOID(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
			const auto alloc2 = reinterpret_cast<alloc2_t>(GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "VirtualAlloc2"));
			if (alloc2)
			{
				MEM_ADDRESS_REQUIREMENTS bounds{};
				bounds.LowestStartingAddress = reinterpret_cast<void*>(low);
				bounds.HighestEndingAddress = reinterpret_cast<void*>(high);
				bounds.Alignment = info.dwAllocationGranularity;
				MEM_EXTENDED_PARAMETER parameter{};
				parameter.Type = MemExtendedParameterAddressRequirements;
				parameter.Pointer = &bounds;
				if (auto page = alloc2(GetCurrentProcess(), nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &parameter, 1))
					return page;
			}
			const uintptr_t granularity = info.dwAllocationGranularity;
			for (uintptr_t cursor = low; cursor <= high - size;)
			{
				MEMORY_BASIC_INFORMATION region{};
				if (!VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)))
				{
					error = GetLastError();
					break;
				}
				const auto base = reinterpret_cast<uintptr_t>(region.BaseAddress);
				const auto end = base + region.RegionSize;
				if (end <= cursor)
					break;
				if (region.State == MEM_FREE)
				{
					auto candidate = (cursor + granularity - 1) & ~(granularity - 1);
					const auto limit = std::min(end, high);
					while (candidate < limit && size <= limit - candidate)
					{
						if (auto page = VirtualAlloc(reinterpret_cast<void*>(candidate), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
							return page;
						error = GetLastError();
						candidate += granularity;
					}
				}
				cursor = end;
			}
		}
		SetLastError(error);
		return nullptr;
	}
	void free_page_near(void* pointer, std::size_t)
	{
		if (pointer)
			VirtualFree(pointer, 0, MEM_RELEASE);
	}
	void* allocate_slot(void* origin)
	{
		return allocate_page_near(origin, MEMORY_SLOT_SIZE);
	}
	void free_slot(void* pointer)
	{
		free_page_near(pointer, MEMORY_SLOT_SIZE);
	}
	void cleanup_buffers()
	{
	}
}
