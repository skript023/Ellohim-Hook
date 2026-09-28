#include "trampoline.hpp"
#include "hde/hde64.h"
#include <cstring>
#include <limits>
#include <algorithm>

namespace ellohim::core
{
	static bool fits32(int64_t value)
	{
		return value >= INT32_MIN && value <= INT32_MAX;
	}
	static void absolute_jump(uint8_t* out, uintptr_t address)
	{
		const uint8_t head[] = {0xff, 0x25, 0, 0, 0, 0};
		std::memcpy(out, head, 6);
		std::memcpy(out + 6, &address, 8);
	}
	static bool build(void* target, void* detour, void* slot, hook_info& info)
	{
		if (!target || !detour || !slot)
			return false;
		info = {};
		info.target = target;
		info.detour = detour;
		info.slot = slot;
		info.trampoline = slot;
		auto src = static_cast<uint8_t*>(target);
		auto dst = static_cast<uint8_t*>(slot);
		auto relay = dst + 480;
		const auto distance = reinterpret_cast<intptr_t>(relay) - (reinterpret_cast<intptr_t>(src) + 5);
		const uint32_t required = fits32(distance) ? 5 : 14;
		hde64s decoded[32]{};
		uint8_t kinds[32]{};
		uint16_t lengths[32]{};
		uintptr_t destinations[32]{};
		uint32_t stolen = 0, emitted = 0;
		bool terminal = false;
		while (stolen < required)
		{
			if (info.count == 32)
				return false;
			if (terminal && src[stolen] != 0x90 && src[stolen] != 0xcc && src[stolen] != 0)
				return false;
			auto& instruction = decoded[info.count];
			const auto size = hde64_disasm(src + stolen, &instruction);
			if (!size || instruction.flags & F_ERROR || stolen + size > sizeof(info.original_bytes))
				return false;
			uint8_t kind = 0;
			uint16_t output = static_cast<uint16_t>(size);
			uintptr_t destination = 0;
			if (instruction.opcode >= 0xe0 && instruction.opcode <= 0xe3)
				return false;
			if (instruction.opcode == 0xe8 || instruction.opcode == 0xe9 || instruction.opcode == 0xeb || (instruction.opcode >= 0x70 && instruction.opcode <= 0x7f) || (instruction.opcode == 0x0f && instruction.opcode2 >= 0x80 && instruction.opcode2 <= 0x8f))
			{
				const auto relative = instruction.flags & F_IMM8 ? int64_t(static_cast<int8_t>(instruction.imm.imm8)) : int64_t(static_cast<int32_t>(instruction.imm.imm32));
				destination = reinterpret_cast<uintptr_t>(src + stolen + size) + relative;
				kind = instruction.opcode == 0xe8 ? 1 : (instruction.opcode == 0xe9 || instruction.opcode == 0xeb) ? 2 :
				                                                                                                     3;
				output = kind == 2 ? 14 : 16;
			}
			if (instruction.opcode == 0xc3 || instruction.opcode == 0xc2 || (kind == 2 && (destination < reinterpret_cast<uintptr_t>(src) || destination >= reinterpret_cast<uintptr_t>(src + required))))
				terminal = true;
			info.old_offsets[info.count] = static_cast<uint8_t>(stolen);
			info.new_offsets[info.count] = static_cast<uint16_t>(emitted);
			kinds[info.count] = kind;
			lengths[info.count] = output;
			destinations[info.count] = destination;
			++info.count;
			stolen += size;
			emitted += output;
			if (emitted + 14 >= 480)
				return false;
		}
		for (uint32_t i = 0; i < info.count; ++i)
		{
			auto& instruction = decoded[i];
			auto from = src + info.old_offsets[i];
			auto to = dst + info.new_offsets[i];
			auto destination = destinations[i];
			if (kinds[i] && destination >= reinterpret_cast<uintptr_t>(src) && destination < reinterpret_cast<uintptr_t>(src + stolen))
			{
				bool found = false;
				for (uint32_t j = 0; j < info.count; ++j)
					if (destination == reinterpret_cast<uintptr_t>(src + info.old_offsets[j]))
					{
						destination = reinterpret_cast<uintptr_t>(dst + info.new_offsets[j]);
						found = true;
						break;
					}
				if (!found)
					return false;
			}
			if (kinds[i] == 1)
			{
				const uint8_t call[] = {0xff, 0x15, 2, 0, 0, 0, 0xeb, 8};
				std::memcpy(to, call, 8);
				std::memcpy(to + 8, &destination, 8);
			}
			else if (kinds[i] == 2)
				absolute_jump(to, destination);
			else if (kinds[i] == 3)
			{
				const auto condition = instruction.opcode == 0x0f ? instruction.opcode2 : instruction.opcode;
				to[0] = 0x70 | ((condition & 0xf) ^ 1);
				to[1] = 14;
				absolute_jump(to + 2, destination);
			}
			else
			{
				std::memcpy(to, from, instruction.len);
				if (!instruction.p_67 && (instruction.flags & F_MODRM) && instruction.modrm_mod == 0 && instruction.modrm_rm == 5)
				{
					const auto address = reinterpret_cast<intptr_t>(from + instruction.len) + static_cast<int32_t>(instruction.disp.disp32);
					const auto displacement = address - reinterpret_cast<intptr_t>(to + instruction.len);
					if (!fits32(displacement))
						return false;
					const auto offset = instruction.len - ((instruction.flags & F_IMM8) ? 1 : 0) - ((instruction.flags & F_IMM16) ? 2 : 0) - ((instruction.flags & F_IMM32) ? 4 : 0) - ((instruction.flags & F_IMM64) ? 8 : 0) - 4;
					const auto value = static_cast<int32_t>(displacement);
					std::memcpy(to + offset, &value, 4);
				}
			}
		}
		absolute_jump(dst + emitted, reinterpret_cast<uintptr_t>(src + stolen));
		info.trampoline_size = emitted + 14;
		info.stolen_size = stolen;
		info.patch_size = required;
		std::memcpy(info.original_bytes, src, stolen);
		if (required == 5)
		{
			info.relay = relay;
			absolute_jump(relay, reinterpret_cast<uintptr_t>(detour));
			info.patch_bytes[0] = 0xe9;
			const auto displacement = static_cast<int32_t>(distance);
			std::memcpy(info.patch_bytes + 1, &displacement, 4);
		}
		else
			absolute_jump(info.patch_bytes, reinterpret_cast<uintptr_t>(detour));
		FlushInstructionCache(GetCurrentProcess(), slot, 512);
		return true;
	}
	bool create_trampoline(void* target, void* detour, void* slot, hook_info& info)
	{
		__try
		{
			return build(target, detour, slot, info);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}
}
