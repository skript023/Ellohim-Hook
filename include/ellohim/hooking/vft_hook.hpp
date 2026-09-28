#pragma once
#include "../common.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace ellohim
{
	class vft_hook
	{
	public:
		// Hook via object instance: instance->vtable[index]
		explicit vft_hook(std::string_view name, void* instance, std::size_t index, void* detour);

		// Hook via direct vtable pointer: vtable[index]
		explicit vft_hook(std::string_view name, void** vtable, std::size_t index, void* detour);

		~vft_hook() noexcept;

		vft_hook(const vft_hook&) = delete;
		vft_hook& operator=(const vft_hook&) = delete;

		vft_hook(vft_hook&& other) noexcept;
		vft_hook& operator=(vft_hook&& other) noexcept;

		bool enable();
		bool disable();

		[[nodiscard]] bool is_enabled() const noexcept { return m_enabled; }
		[[nodiscard]] std::string_view name() const noexcept { return m_name; }
		[[nodiscard]] void* get_original_ptr() const noexcept { return m_original; }

		template<typename T>
		[[nodiscard]] T get_original() const noexcept
		{
			return reinterpret_cast<T>(m_original);
		}

		template<auto Detour>
		struct vft_helper
		{
			static inline vft_hook* m_hook{nullptr};
		};

		template<auto Detour>
		static void add(std::string_view name, void* instance, std::size_t index)
		{
			auto* hook = new vft_hook(name, instance, index, reinterpret_cast<void*>(Detour));
			vft_helper<Detour>::m_hook = hook;
			m_vft_hooks.push_back(hook);
		}

		template<auto Detour>
		static auto get_original()
		{
			auto* hook = vft_helper<Detour>::m_hook;
			if (!hook)
				throw std::runtime_error("Attempted to call uninitialized vft_hook");
			return reinterpret_cast<decltype(Detour)>(hook->get_original_ptr());
		}

		static std::vector<vft_hook*>& hooks() { return m_vft_hooks; }
		static bool enable_all();
		static bool disable_all();

	private:
		std::string m_name;
		void** m_slot{nullptr};
		void* m_detour{nullptr};
		void* m_original{nullptr};
		bool m_enabled{false};

		static inline std::vector<vft_hook*> m_vft_hooks;
	};
}
