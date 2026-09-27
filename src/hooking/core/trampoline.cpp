#include "trampoline.hpp"

#if defined(_M_X64) || defined(__x86_64__)
#include "hde/hde64.h"
#else
#include "hde/hde32.h"
#endif

#include <cstring>

namespace ellohim::core
{
#pragma pack(push, 1)
	struct jmp_abs_x64
	{
		uint8_t opcode0{0xFF};
		uint8_t opcode1{0x25};
		uint32_t dummy{0x00000000};
		uint64_t address{0};
	};
#pragma pack(pop)

	bool create_trampoline(void* target, void* detour, void* slot, hook_info& out_info)
	{
		if (!target || !detour || !slot)
			return false;

		out_info.target = target;
		out_info.detour = detour;
		out_info.slot = slot;

		auto* src = static_cast<uint8_t*>(target);
		auto* tramp = static_cast<uint8_t*>(slot);

#if defined(_M_X64) || defined(__x86_64__)
		// In x64, slot is 64 bytes.
		// Allocate relay at slot + 48 (16 bytes aligned)
		auto* relay = tramp + 48;
		out_info.relay = relay;

		// Write 14-byte absolute jump to detour in relay
		auto* relay_jmp = reinterpret_cast<jmp_abs_x64*>(relay);
		relay_jmp->opcode0 = 0xFF;
		relay_jmp->opcode1 = 0x25;
		relay_jmp->dummy = 0x00000000;
		relay_jmp->address = reinterpret_cast<uint64_t>(detour);

		// Prepare 5-byte relative jump at target -> relay
		out_info.patch_bytes[0] = 0xE9;
		intptr_t rel_offset = reinterpret_cast<intptr_t>(relay) - (reinterpret_cast<intptr_t>(target) + 5);
		std::memcpy(&out_info.patch_bytes[1], &rel_offset, sizeof(int32_t));
		out_info.patch_size = 5;
#else
		// In x86, slot is 32 bytes.
		// 5-byte relative jump at target directly to detour
		out_info.relay = detour;
		out_info.patch_bytes[0] = 0xE9;
		intptr_t rel_offset = reinterpret_cast<intptr_t>(detour) - (reinterpret_cast<intptr_t>(target) + 5);
		std::memcpy(&out_info.patch_bytes[1], &rel_offset, sizeof(int32_t));
		out_info.patch_size = 5;
#endif

		// Disassemble instructions at target until we have at least 5 bytes
		uint32_t stolen_bytes = 0;
		uint32_t tramp_bytes = 0;

		while (stolen_bytes < 5)
		{
#if defined(_M_X64) || defined(__x86_64__)
			hde64s hs{};
			uint32_t len = hde64_disasm(src + stolen_bytes, &hs);
#else
			hde32s hs{};
			uint32_t len = hde32_disasm(src + stolen_bytes, &hs);
#endif
			if (len == 0 || (hs.flags & F_ERROR))
				return false;

			// Copy instruction to trampoline
			std::memcpy(tramp + tramp_bytes, src + stolen_bytes, len);

#if defined(_M_X64) || defined(__x86_64__)
			// Handle RIP-relative addressing (ModR/M with mod = 00 and r/m = 101)
			if ((hs.flags & F_MODRM) && (hs.modrm_mod == 0x00) && (hs.modrm_rm == 0x05))
			{
				auto* inst_src = src + stolen_bytes;
				auto* inst_dst = tramp + tramp_bytes;

				intptr_t target_abs = reinterpret_cast<intptr_t>(inst_src + len) + hs.disp.disp32;
				intptr_t new_disp = target_abs - reinterpret_cast<intptr_t>(inst_dst + len);

				// Find displacement offset in instruction
				uint8_t disp_offset = hs.len - ((hs.flags & F_IMM8) ? 1 : 0)
				                             - ((hs.flags & F_IMM16) ? 2 : 0)
				                             - ((hs.flags & F_IMM32) ? 4 : 0)
				                             - ((hs.flags & F_IMM64) ? 8 : 0)
				                             - 4;

				std::memcpy(inst_dst + disp_offset, &new_disp, sizeof(int32_t));
			}
			// Handle 32-bit relative direct JMP (E9) or CALL (E8)
			else if (hs.opcode == 0xE9 || hs.opcode == 0xE8)
			{
				auto* inst_src = src + stolen_bytes;
				auto* inst_dst = tramp + tramp_bytes;

				intptr_t target_abs = reinterpret_cast<intptr_t>(inst_src + 5) + static_cast<int32_t>(hs.imm.imm32);
				intptr_t new_disp = target_abs - reinterpret_cast<intptr_t>(inst_dst + 5);

				std::memcpy(inst_dst + 1, &new_disp, sizeof(int32_t));
			}
#else
			// In x86, handle relative JMP (E9) or CALL (E8)
			if (hs.opcode == 0xE9 || hs.opcode == 0xE8)
			{
				auto* inst_src = src + stolen_bytes;
				auto* inst_dst = tramp + tramp_bytes;

				intptr_t target_abs = reinterpret_cast<intptr_t>(inst_src + 5) + static_cast<int32_t>(hs.imm.imm32);
				intptr_t new_disp = target_abs - reinterpret_cast<intptr_t>(inst_dst + 5);

				std::memcpy(inst_dst + 1, &new_disp, sizeof(int32_t));
			}
#endif

			stolen_bytes += len;
			tramp_bytes += len;
		}

		out_info.stolen_size = stolen_bytes;
		std::memcpy(out_info.original_bytes, target, stolen_bytes);

#if defined(_M_X64) || defined(__x86_64__)
		// Append 14-byte absolute jump back to (target + stolen_bytes)
		auto* back_jmp = reinterpret_cast<jmp_abs_x64*>(tramp + tramp_bytes);
		back_jmp->opcode0 = 0xFF;
		back_jmp->opcode1 = 0x25;
		back_jmp->dummy = 0x00000000;
		back_jmp->address = reinterpret_cast<uint64_t>(src + stolen_bytes);
#else
		// Append 5-byte relative jump back to (target + stolen_bytes)
		tramp[tramp_bytes] = 0xE9;
		intptr_t back_rel = reinterpret_cast<intptr_t>(src + stolen_bytes) - (reinterpret_cast<intptr_t>(tramp + tramp_bytes) + 5);
		std::memcpy(&tramp[tramp_bytes + 1], &back_rel, sizeof(int32_t));
#endif

		out_info.trampoline = slot;
		return true;
	}
}
