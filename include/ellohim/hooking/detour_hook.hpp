#pragma once
#include "detour_base.hpp"
#include "../memory/handle.hpp"

namespace ellohim
{
	class detour_hook : public detour_base
	{
	public:
		explicit detour_hook(std::string_view name, void* target, void* detour);
		~detour_hook() noexcept override;

		bool enable() override;
		bool disable() override;

		void enable_immediately();
		void disable_immediately();

		void* get_original_ptr() override;

		template<typename T>
		T get_original()
		{
			return reinterpret_cast<T>(get_original_ptr());
		}

		template<auto T>
		static void add(std::string_view name, void* target)
		{
			detour_base::add<T>(new detour_hook(name, target, reinterpret_cast<void*>(T)));
		}

		template<auto T>
		static auto get_original()
		{
			return detour_base::get_original<T>();
		}

		void fix_hook_address();

	private:
		void* m_target{nullptr};
		void* m_detour{nullptr};
		void* m_slot{nullptr};
		void* m_trampoline{nullptr};

		uint8_t m_original_bytes[32]{};
		uint8_t m_patch_bytes[8]{};
		uint32_t m_patch_size{0};
		uint32_t m_stolen_size{0};
	};
}
