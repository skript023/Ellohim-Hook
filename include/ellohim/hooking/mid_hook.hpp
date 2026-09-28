#pragma once
#include "../common.hpp"
#include "detour_hook.hpp"
#include "../memory/handle.hpp"
#include <vector>
#include <string_view>

namespace ellohim
{
	union xmm_reg {
		uint8_t u8[16];
		uint16_t u16[8];
		uint32_t u32[4];
		uint64_t u64[2];
		float f32[4];
		double f64[2];
	};

#if defined(_M_X64) || defined(__x86_64__)
	struct mid_context
	{
		xmm_reg xmm[16]; // XMM0 - XMM15
		uint64_t rsp;    // Snapshot only; changing it does not redirect execution
		uint64_t r15;
		uint64_t r14;
		uint64_t r13;
		uint64_t r12;
		uint64_t r11;
		uint64_t r10;
		uint64_t r9;
		uint64_t r8;
		uint64_t rbp;
		uint64_t rdi;
		uint64_t rsi;
		uint64_t rdx;
		uint64_t rcx;
		uint64_t rbx;
		uint64_t rax;
		uint64_t rflags;
		uintptr_t rip; // Snapshot only; changing it does not redirect execution
	};
#else
	struct mid_context
	{
		uint32_t eflags;
		uint32_t edi;
		uint32_t esi;
		uint32_t ebp;
		uint32_t esp;
		uint32_t ebx;
		uint32_t edx;
		uint32_t ecx;
		uint32_t eax;
		uintptr_t eip;
	};
#endif

	using mid_callback_t = void (*)(mid_context& ctx);

	class mid_hook
	{
	public:
		explicit mid_hook(std::string_view name, void* target, mid_callback_t callback);
		~mid_hook() noexcept;

		mid_hook(const mid_hook&) = delete;
		mid_hook& operator=(const mid_hook&) = delete;

		mid_hook(mid_hook&& other) noexcept;
		mid_hook& operator=(mid_hook&& other) noexcept;

		bool enable();
		bool disable();

		[[nodiscard]] bool is_enabled() const noexcept
		{
			return m_enabled;
		}
		[[nodiscard]] std::string_view name() const noexcept
		{
			return m_name;
		}
		[[nodiscard]] void* target() const noexcept
		{
			return m_target;
		}

		template<auto Callback>
		static void add(std::string_view name, void* target)
		{
			auto* hook = new mid_hook(name, target, Callback);
			m_mid_hooks.push_back(hook);
		}

		static std::vector<mid_hook*>& hooks()
		{
			return m_mid_hooks;
		}
		static bool enable_all();
		static bool disable_all();

	private:
		std::unique_ptr<detour_hook> m_backend;
		std::string m_name;
		void* m_target{nullptr};
		mid_callback_t m_callback{nullptr};
		void* m_stub{nullptr};
		std::size_t m_stub_size{0};

		uint8_t m_original_bytes[32]{};
		uint8_t m_patch_bytes[8]{};
		uint32_t m_patch_size{0};
		uint32_t m_stolen_size{0};
		bool m_enabled{false};

		static inline std::vector<mid_hook*> m_mid_hooks;
		void build_stub();
		void fix_hook_address();
	};
}
