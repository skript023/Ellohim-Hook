#pragma once
#include "../common.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace ellohim
{
	class iat_hook
	{
	public:
		explicit iat_hook(std::string_view name, HMODULE module_to_hook, std::string_view target_dll, std::string_view function_name, void* detour);
		~iat_hook() noexcept;

		iat_hook(const iat_hook&) = delete;
		iat_hook& operator=(const iat_hook&) = delete;

		iat_hook(iat_hook&& other) = delete;
		iat_hook& operator=(iat_hook&& other) = delete;

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
		struct iat_helper
		{
			static inline iat_hook* m_hook{nullptr};
		};

		template<auto Detour>
		static void add(std::string_view name, HMODULE module_to_hook, std::string_view target_dll, std::string_view function_name)
		{
			if (iat_helper<Detour>::m_hook) throw std::logic_error("Duplicate IAT callback");
			auto hook = std::make_unique<iat_hook>(name, module_to_hook, target_dll, function_name, reinterpret_cast<void*>(Detour));
			m_iat_hooks.push_back(hook.get());
			hook->m_clear_binding = [](iat_hook* value) {
				if (iat_helper<Detour>::m_hook == value) iat_helper<Detour>::m_hook = nullptr;
			};
			iat_helper<Detour>::m_hook = hook.release();
		}

		template<auto Detour>
		static auto get_original()
		{
			auto* hook = iat_helper<Detour>::m_hook;
			if (!hook)
				throw std::runtime_error("Attempted to call uninitialized iat_hook");
			return reinterpret_cast<decltype(Detour)>(hook->get_original_ptr());
		}

		static std::vector<iat_hook*>& hooks() { return m_iat_hooks; }
		static bool enable_all();
		static bool disable_all();

	private:
		std::string m_name;
		void** m_iat_slot{nullptr};
		void* m_detour{nullptr};
		void* m_original{nullptr};
		bool m_enabled{false};
		bool m_writable{false};
		void (*m_clear_binding)(iat_hook*){nullptr};

		static inline std::vector<iat_hook*> m_iat_hooks;
	};
}
