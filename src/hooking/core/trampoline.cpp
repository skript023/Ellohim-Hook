#include "trampoline.hpp"
#include <Zydis/Zydis.h>
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
		auto* relay = tramp + 48;
		out_info.relay = relay;

		auto* relay_jmp = reinterpret_cast<jmp_abs_x64*>(relay);
		relay_jmp->opcode0 = 0xFF;
		relay_jmp->opcode1 = 0x25;
		relay_jmp->dummy = 0x00000000;
		relay_jmp->address = reinterpret_cast<uint64_t>(detour);

		out_info.patch_bytes[0] = 0xE9;
		intptr_t rel_offset = reinterpret_cast<intptr_t>(relay) - (reinterpret_cast<intptr_t>(target) + 5);
		std::memcpy(&out_info.patch_bytes[1], &rel_offset, sizeof(int32_t));
		out_info.patch_size = 5;
#else
		out_info.relay = detour;
		out_info.patch_bytes[0] = 0xE9;
		intptr_t rel_offset = reinterpret_cast<intptr_t>(detour) - (reinterpret_cast<intptr_t>(target) + 5);
		std::memcpy(&out_info.patch_bytes[1], &rel_offset, sizeof(int32_t));
		out_info.patch_size = 5;
#endif

		ZydisDecoder decoder;
#if defined(_M_X64) || defined(__x86_64__)
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif

		uint32_t stolen_bytes = 0;
		uint32_t tramp_bytes = 0;

		while (stolen_bytes < 5)
		{
			ZydisDecodedInstruction insn{};
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, src + stolen_bytes, 15, &insn, operands)))
			{
				return false;
			}

			// Copy raw instruction to trampoline
			std::memcpy(tramp + tramp_bytes, src + stolen_bytes, insn.length);

#if defined(_M_X64) || defined(__x86_64__)
			// Check for RIP-relative memory operand or relative branch
			for (uint8_t i = 0; i < insn.operand_count_visible; ++i)
			{
				if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[i].mem.base == ZYDIS_REGISTER_RIP)
				{
					ZyanU64 target_abs = 0;
					ZydisCalcAbsoluteAddress(&insn, &operands[i], reinterpret_cast<ZyanU64>(src + stolen_bytes), &target_abs);

					ZyanI64 new_disp = static_cast<ZyanI64>(target_abs) - static_cast<ZyanI64>(reinterpret_cast<uintptr_t>(tramp + tramp_bytes) + insn.length);
					std::memcpy(tramp + tramp_bytes + insn.raw.disp.offset, &new_disp, sizeof(int32_t));
				}
				else if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative)
				{
					ZyanU64 target_abs = 0;
					ZydisCalcAbsoluteAddress(&insn, &operands[i], reinterpret_cast<ZyanU64>(src + stolen_bytes), &target_abs);

					ZyanI64 new_disp = static_cast<ZyanI64>(target_abs) - static_cast<ZyanI64>(reinterpret_cast<uintptr_t>(tramp + tramp_bytes) + insn.length);
					std::memcpy(tramp + tramp_bytes + insn.raw.imm[0].offset, &new_disp, sizeof(int32_t));
				}
			}
#else
			for (uint8_t i = 0; i < insn.operand_count_visible; ++i)
			{
				if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative)
				{
					ZyanU64 target_abs = 0;
					ZydisCalcAbsoluteAddress(&insn, &operands[i], reinterpret_cast<ZyanU64>(src + stolen_bytes), &target_abs);

					ZyanI64 new_disp = static_cast<ZyanI64>(target_abs) - static_cast<ZyanI64>(reinterpret_cast<uintptr_t>(tramp + tramp_bytes) + insn.length);
					std::memcpy(tramp + tramp_bytes + insn.raw.imm[0].offset, &new_disp, sizeof(int32_t));
				}
			}
#endif

			stolen_bytes += insn.length;
			tramp_bytes += insn.length;
		}

		out_info.stolen_size = stolen_bytes;
		std::memcpy(out_info.original_bytes, target, stolen_bytes);

#if defined(_M_X64) || defined(__x86_64__)
		auto* back_jmp = reinterpret_cast<jmp_abs_x64*>(tramp + tramp_bytes);
		back_jmp->opcode0 = 0xFF;
		back_jmp->opcode1 = 0x25;
		back_jmp->dummy = 0x00000000;
		back_jmp->address = reinterpret_cast<uint64_t>(src + stolen_bytes);
#else
		tramp[tramp_bytes] = 0xE9;
		intptr_t back_rel = reinterpret_cast<intptr_t>(src + stolen_bytes) - (reinterpret_cast<intptr_t>(tramp + tramp_bytes) + 5);
		std::memcpy(&tramp[tramp_bytes + 1], &back_rel, sizeof(int32_t));
#endif

		out_info.trampoline = slot;
		return true;
	}
}
