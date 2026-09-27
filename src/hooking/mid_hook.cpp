#include "ellohim/hooking/mid_hook.hpp"
#include "ellohim/logger.hpp"
#include "core/buffer.hpp"
#include "core/thread_freezer.hpp"

#if defined(_M_X64) || defined(__x86_64__)
#include "core/hde/hde64.h"
#else
#include "core/hde/hde32.h"
#endif

#include <cstring>
#include <algorithm>

namespace ellohim
{
	static bool resolve_jump_chain(void*& target)
	{
		__try
		{
			auto ptr = memory::handle(target);
			std::size_t max_depth = 16;
			bool resolved = true;

			while (resolved && max_depth-- > 0 && ptr)
			{
				const auto opcode = ptr.as<std::uint8_t&>();
				if (opcode == 0xE9) // jmp rel32
				{
					ptr = ptr.add(1).rip();
				}
				else if (opcode == 0xEB) // jmp rel8
				{
					const auto rel8 = ptr.add(1).as<std::int8_t&>();
					ptr = ptr.add(2).add(rel8);
				}
#if defined(_M_X64) || defined(__x86_64__)
				else if (opcode == 0xFF && ptr.add(1).as<std::uint8_t&>() == 0x25) // jmp qword ptr [rip + disp32]
				{
					auto* target_ptr = ptr.add(2).rip().as<void**>();
					if (target_ptr && *target_ptr)
					{
						ptr = memory::handle(*target_ptr);
					}
					else
					{
						resolved = false;
					}
				}
#endif
				else
				{
					resolved = false;
				}
			}

			target = ptr.as<void*>();
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	mid_hook::mid_hook(std::string_view name, void* target, mid_callback_t callback) :
	    m_name(name),
	    m_target(target),
	    m_callback(callback),
	    m_enabled(false)
	{
		logger::info("Creating mid_hook '{}' at {:p}", m_name, m_target);

		if (!m_target)
		{
			throw std::runtime_error(std::format("Failed to create mid_hook '{}': target address is null", m_name));
		}
		if (!m_callback)
		{
			throw std::runtime_error(std::format("Failed to create mid_hook '{}': callback function is null", m_name));
		}

		fix_hook_address();
		build_stub();

		logger::info("mid_hook '{}' stub successfully built at {:p}", m_name, m_stub);
	}

	mid_hook::~mid_hook() noexcept
	{
		if (m_enabled)
		{
			disable();
		}

		if (m_stub)
		{
			core::free_page_near(m_stub, m_stub_size);
			m_stub = nullptr;
		}

		std::erase(m_mid_hooks, this);
		logger::info("Removed mid_hook '{}'", m_name);
	}

	mid_hook::mid_hook(mid_hook&& other) noexcept :
	    m_name(std::move(other.m_name)),
	    m_target(other.m_target),
	    m_callback(other.m_callback),
	    m_stub(other.m_stub),
	    m_stub_size(other.m_stub_size),
	    m_patch_size(other.m_patch_size),
	    m_stolen_size(other.m_stolen_size),
	    m_enabled(other.m_enabled)
	{
		std::memcpy(m_original_bytes, other.m_original_bytes, sizeof(m_original_bytes));
		std::memcpy(m_patch_bytes, other.m_patch_bytes, sizeof(m_patch_bytes));

		other.m_target = nullptr;
		other.m_callback = nullptr;
		other.m_stub = nullptr;
		other.m_stub_size = 0;
		other.m_enabled = false;
	}

	mid_hook& mid_hook::operator=(mid_hook&& other) noexcept
	{
		if (this != &other)
		{
			if (m_enabled)
			{
				disable();
			}
			if (m_stub)
			{
				core::free_page_near(m_stub, m_stub_size);
			}

			m_name = std::move(other.m_name);
			m_target = other.m_target;
			m_callback = other.m_callback;
			m_stub = other.m_stub;
			m_stub_size = other.m_stub_size;
			m_patch_size = other.m_patch_size;
			m_stolen_size = other.m_stolen_size;
			m_enabled = other.m_enabled;

			std::memcpy(m_original_bytes, other.m_original_bytes, sizeof(m_original_bytes));
			std::memcpy(m_patch_bytes, other.m_patch_bytes, sizeof(m_patch_bytes));

			other.m_target = nullptr;
			other.m_callback = nullptr;
			other.m_stub = nullptr;
			other.m_stub_size = 0;
			other.m_enabled = false;
		}
		return *this;
	}

	void mid_hook::fix_hook_address()
	{
		if (!resolve_jump_chain(m_target))
		{
			logger::error("Failed to fix hook address for mid_hook '{}'", m_name);
			throw std::runtime_error(std::format("Failed to fix hook address for mid_hook '{}'", m_name));
		}
	}

	void mid_hook::build_stub()
	{
		m_stub_size = 4096;
		m_stub = core::allocate_page_near(m_target, m_stub_size);
		if (!m_stub)
		{
			throw std::runtime_error(std::format("Failed to allocate near-memory for mid_hook '{}'", m_name));
		}

		std::vector<uint8_t> code;
		code.reserve(512);

		auto emit8 = [&](uint8_t b) { code.push_back(b); };
		auto emit16 = [&](uint16_t w) {
			code.push_back(w & 0xFF);
			code.push_back((w >> 8) & 0xFF);
		};
		auto emit32 = [&](uint32_t d) {
			code.push_back(d & 0xFF);
			code.push_back((d >> 8) & 0xFF);
			code.push_back((d >> 16) & 0xFF);
			code.push_back((d >> 24) & 0xFF);
		};
		auto emit64 = [&](uint64_t q) {
			emit32(static_cast<uint32_t>(q & 0xFFFFFFFF));
			emit32(static_cast<uint32_t>((q >> 32) & 0xFFFFFFFF));
		};

#if defined(_M_X64) || defined(__x86_64__)
		// 1. Push RIP (target address)
		emit8(0x48); emit8(0xB8); emit64(reinterpret_cast<uint64_t>(m_target)); // mov rax, target
		emit8(0x50);                                                            // push rax

		// 2. Push RFLAGS
		emit8(0x9C); // pushfq

		// 3. Push General Purpose Registers (15 registers = 120 bytes)
		emit8(0x50); // push rax
		emit8(0x53); // push rbx
		emit8(0x51); // push rcx
		emit8(0x52); // push rdx
		emit8(0x56); // push rsi
		emit8(0x57); // push rdi
		emit8(0x55); // push rbp
		emit8(0x41); emit8(0x50); // push r8
		emit8(0x41); emit8(0x51); // push r9
		emit8(0x41); emit8(0x52); // push r10
		emit8(0x41); emit8(0x53); // push r11
		emit8(0x41); emit8(0x54); // push r12
		emit8(0x41); emit8(0x55); // push r13
		emit8(0x41); emit8(0x56); // push r14
		emit8(0x41); emit8(0x57); // push r15

		// 4. Push original RSP (which was rsp + 136 before our pushes)
		// lea rax, [rsp + 136] -> 48 8D 84 24 88 00 00 00
		emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(136);
		emit8(0x50); // push rax

		// 5. Allocate space for 16 XMM registers (256 bytes)
		// sub rsp, 256 -> 48 81 EC 00 01 00 00
		emit8(0x48); emit8(0x81); emit8(0xEC); emit32(256);

		// 6. Save XMM0-XMM15 to [rsp + i*16] using movdqu
		for (uint32_t i = 0; i < 16; ++i)
		{
			if (i < 8)
			{
				emit8(0xF3); emit8(0x0F); emit8(0x7F);
				emit8(static_cast<uint8_t>(0x84 | (i << 3)));
				emit8(0x24);
				emit32(i * 16);
			}
			else
			{
				emit8(0xF3); emit8(0x44); emit8(0x0F); emit8(0x7F);
				emit8(static_cast<uint8_t>(0x84 | ((i - 8) << 3)));
				emit8(0x24);
				emit32(i * 16);
			}
		}

		// 7. Set first parameter (RCX) = &mid_context = rsp
		// lea rcx, [rsp] -> 48 8D 0C 24
		emit8(0x48); emit8(0x8D); emit8(0x0C); emit8(0x24);

		// 8. Align stack and allocate 32-byte shadow space for Win64 ABI (sub rsp, 40)
		// sub rsp, 0x28 -> 48 83 EC 28
		emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);

		// 9. Call user callback
		emit8(0x48); emit8(0xB8); emit64(reinterpret_cast<uint64_t>(m_callback)); // mov rax, callback
		emit8(0xFF); emit8(0xD0);                                                 // call rax

		// 10. Restore stack shadow space
		// add rsp, 0x28 -> 48 83 C4 28
		emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

		// 11. Restore XMM0-XMM15 from [rsp + i*16]
		for (uint32_t i = 0; i < 16; ++i)
		{
			if (i < 8)
			{
				emit8(0xF3); emit8(0x0F); emit8(0x6F);
				emit8(static_cast<uint8_t>(0x84 | (i << 3)));
				emit8(0x24);
				emit32(i * 16);
			}
			else
			{
				emit8(0xF3); emit8(0x44); emit8(0x0F); emit8(0x6F);
				emit8(static_cast<uint8_t>(0x84 | ((i - 8) << 3)));
				emit8(0x24);
				emit32(i * 16);
			}
		}

		// 12. Deallocate XMM space
		// add rsp, 256 -> 48 81 C4 00 01 00 00
		emit8(0x48); emit8(0x81); emit8(0xC4); emit32(256);

		// 13. Skip original RSP slot
		emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);

		// 14. Pop GPRs
		emit8(0x41); emit8(0x5F); // pop r15
		emit8(0x41); emit8(0x5E); // pop r14
		emit8(0x41); emit8(0x5D); // pop r13
		emit8(0x41); emit8(0x5C); // pop r12
		emit8(0x41); emit8(0x5B); // pop r11
		emit8(0x41); emit8(0x5A); // pop r10
		emit8(0x41); emit8(0x59); // pop r9
		emit8(0x41); emit8(0x58); // pop r8
		emit8(0x5D);             // pop rbp
		emit8(0x5F);             // pop rdi
		emit8(0x5E);             // pop rsi
		emit8(0x5A);             // pop rdx
		emit8(0x59);             // pop rcx
		emit8(0x5B);             // pop rbx
		emit8(0x58);             // pop rax

		// 15. Restore RFLAGS
		emit8(0x9D); // popfq

		// 16. Skip target RIP slot
		emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);

		// 17. Disassemble stolen instructions from target
		auto* src = static_cast<uint8_t*>(m_target);
		uint32_t stolen_bytes = 0;

		while (stolen_bytes < 5)
		{
			hde64s hs{};
			uint32_t len = hde64_disasm(src + stolen_bytes, &hs);
			if (len == 0 || (hs.flags & F_ERROR))
			{
				throw std::runtime_error(std::format("Disassembly failed for mid_hook '{}' at offset {}", m_name, stolen_bytes));
			}

			std::size_t inst_dst_offset = code.size();
			// Copy instruction
			for (uint32_t b = 0; b < len; ++b)
			{
				emit8(src[stolen_bytes + b]);
			}

			// Relocate RIP-relative displacement if present
			if ((hs.flags & F_MODRM) && (hs.modrm_mod == 0x00) && (hs.modrm_rm == 0x05))
			{
				auto* inst_src = src + stolen_bytes;
				auto* inst_dst = static_cast<uint8_t*>(m_stub) + inst_dst_offset;

				intptr_t target_abs = reinterpret_cast<intptr_t>(inst_src + len) + hs.disp.disp32;
				intptr_t new_disp = target_abs - reinterpret_cast<intptr_t>(inst_dst + len);

				uint8_t disp_offset = hs.len - ((hs.flags & F_IMM8) ? 1 : 0)
				                             - ((hs.flags & F_IMM16) ? 2 : 0)
				                             - ((hs.flags & F_IMM32) ? 4 : 0)
				                             - ((hs.flags & F_IMM64) ? 8 : 0)
				                             - 4;

				std::memcpy(&code[inst_dst_offset + disp_offset], &new_disp, sizeof(int32_t));
			}
			else if (hs.opcode == 0xE9 || hs.opcode == 0xE8)
			{
				auto* inst_src = src + stolen_bytes;
				auto* inst_dst = static_cast<uint8_t*>(m_stub) + inst_dst_offset;

				intptr_t target_abs = reinterpret_cast<intptr_t>(inst_src + 5) + static_cast<int32_t>(hs.imm.imm32);
				intptr_t new_disp = target_abs - reinterpret_cast<intptr_t>(inst_dst + 5);

				std::memcpy(&code[inst_dst_offset + 1], &new_disp, sizeof(int32_t));
			}

			stolen_bytes += len;
		}

		m_stolen_size = stolen_bytes;
		std::memcpy(m_original_bytes, m_target, stolen_bytes);

		// 18. Append 14-byte absolute jump back to target + stolen_bytes
		// FF 25 00000000 <target + stolen_bytes>
		emit8(0xFF); emit8(0x25); emit32(0);
		emit64(reinterpret_cast<uint64_t>(src + stolen_bytes));

#else
		// 32-bit implementation
		emit8(0x9C); // pushfd
		emit8(0x50); emit8(0x53); emit8(0x51); emit8(0x52); // push eax, ebx, ecx, edx
		emit8(0x56); emit8(0x57); emit8(0x55);             // push esi, edi, ebp
		// lea eax, [esp + 32]; push eax
		emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x20); emit8(0x50);
		// push esp (pointer to context)
		emit8(0x54);
		emit8(0xB8); emit32(reinterpret_cast<uint32_t>(m_callback)); // mov eax, callback
		emit8(0xFF); emit8(0xD0);                                   // call eax
		emit8(0x58);                                                // pop eax
		emit8(0x58);                                                // pop eax (orig esp)
		emit8(0x5D); emit8(0x5F); emit8(0x5E);                      // pop ebp, edi, esi
		emit8(0x5A); emit8(0x59); emit8(0x5B); emit8(0x58);        // pop edx, ecx, ebx, eax
		emit8(0x9D);                                                // popfd

		// Copy stolen instructions
		auto* src = static_cast<uint8_t*>(m_target);
		uint32_t stolen_bytes = 0;
		while (stolen_bytes < 5)
		{
			hde32s hs{};
			uint32_t len = hde32_disasm(src + stolen_bytes, &hs);
			if (len == 0 || (hs.flags & F_ERROR))
				throw std::runtime_error("Disassembly failed in 32-bit mid_hook");

			for (uint32_t b = 0; b < len; ++b)
				emit8(src[stolen_bytes + b]);

			stolen_bytes += len;
		}

		m_stolen_size = stolen_bytes;
		std::memcpy(m_original_bytes, m_target, stolen_bytes);

		// Jump back
		emit8(0xE9);
		intptr_t back_rel = reinterpret_cast<intptr_t>(src + stolen_bytes) - (reinterpret_cast<intptr_t>(m_stub) + code.size() + 4);
		emit32(static_cast<uint32_t>(back_rel));
#endif

		// Copy generated stub code to executable memory
		std::memcpy(m_stub, code.data(), code.size());
		FlushInstructionCache(GetCurrentProcess(), m_stub, code.size());

		// Prepare 5-byte relative jump patch at target
		m_patch_bytes[0] = 0xE9;
		intptr_t rel_offset = reinterpret_cast<intptr_t>(m_stub) - (reinterpret_cast<intptr_t>(m_target) + 5);
		std::memcpy(&m_patch_bytes[1], &rel_offset, sizeof(int32_t));
		m_patch_size = 5;
	}

	bool mid_hook::enable()
	{
		if (m_enabled || !m_target || !m_stub)
			return true;

		core::thread_freezer freezer;

		DWORD old_protect{};
		if (!VirtualProtect(m_target, m_patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
		{
			throw std::runtime_error(std::format("VirtualProtect failed while enabling mid_hook '{}'", m_name));
		}

		std::memcpy(m_target, m_patch_bytes, m_patch_size);
		VirtualProtect(m_target, m_patch_size, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_target, m_patch_size);

		m_enabled = true;
		return true;
	}

	bool mid_hook::disable()
	{
		if (!m_enabled || !m_target)
			return true;

		core::thread_freezer freezer;

		DWORD old_protect{};
		if (!VirtualProtect(m_target, m_patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
		{
			return false;
		}

		std::memcpy(m_target, m_original_bytes, m_patch_size);
		VirtualProtect(m_target, m_patch_size, old_protect, &old_protect);
		FlushInstructionCache(GetCurrentProcess(), m_target, m_patch_size);

		m_enabled = false;
		return true;
	}

	bool mid_hook::enable_all()
	{
		bool status = true;
		for (auto* hook : m_mid_hooks)
		{
			status = hook->enable() && status;
		}
		return status;
	}

	bool mid_hook::disable_all()
	{
		bool status = true;
		for (auto* hook : m_mid_hooks)
		{
			status = hook->disable() && status;
		}
		return status;
	}
}
