#pragma once
#include "../common.hpp"

namespace ellohim
{
	class detour_base
	{
	protected:
		std::string m_name;
		bool m_enabled{false};
		void (*m_clear_binding)(detour_base*){nullptr};

	public:
		explicit detour_base(std::string_view name, bool register_hook = true);
		virtual ~detour_base();

		detour_base(const detour_base&) = delete;
		detour_base(detour_base&&) noexcept = delete;
		detour_base& operator=(const detour_base&) = delete;
		detour_base& operator=(detour_base&&) noexcept = delete;

		[[nodiscard]] std::string_view name() const noexcept
		{
			return m_name;
		}

		[[nodiscard]] bool is_enabled() const noexcept
		{
			return m_enabled;
		}

		virtual bool enable() = 0;
		virtual bool disable() = 0;
		virtual void* get_original_ptr() = 0;

	public:
		template<auto detour_function>
		struct detour_helper
		{
			static inline detour_base* m_hook{nullptr};
		};

		template<auto detour_function>
		static void add(detour_base* hook);

		template<auto detour_function, typename T = detour_base>
		static T* get();

		template<auto detour_function>
		static auto get_original();

		static std::vector<detour_base*>& hooks();

		static bool enable_all();
		static bool disable_all();
		// Only hooks explicitly transferred through add() are owned by the registry.
		static bool destroy_owned();
		static bool any_enabled();

	private:
		static inline std::vector<detour_base*> m_detour_bases;
		bool m_registry_owned{false};
	};

	template<auto detour_function>
	inline void detour_base::add(detour_base* hook)
	{
		if (!hook)
			throw std::invalid_argument("Null hook registration");
		if (detour_helper<detour_function>::m_hook)
			throw std::logic_error("Callback already has a registered hook");
		hook->m_registry_owned = true;
		detour_helper<detour_function>::m_hook = hook;
		hook->m_clear_binding = [](detour_base* value) {
			if (detour_helper<detour_function>::m_hook == value)
			{
				detour_helper<detour_function>::m_hook = nullptr;
			}
		};
	}

	template<auto detour_function, typename T>
	inline T* detour_base::get()
	{
		return reinterpret_cast<T*>(detour_helper<detour_function>::m_hook);
	}

	template<auto detour_function>
	inline auto detour_base::get_original()
	{
		auto* hook = detour_helper<detour_function>::m_hook;
		if (!hook)
		{
			throw std::runtime_error("Attempted to call uninitialized detour hook");
		}
		return reinterpret_cast<decltype(detour_function)>(hook->get_original_ptr());
	}
}
