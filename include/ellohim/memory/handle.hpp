#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace memory
{
	class handle
	{
	public:
		handle(void* ptr = nullptr) noexcept : m_ptr(ptr) {}
		explicit handle(std::uintptr_t ptr) noexcept : m_ptr(reinterpret_cast<void*>(ptr)) {}

		template<typename T>
		[[nodiscard]] std::enable_if_t<std::is_pointer_v<T>, T> as() const noexcept
		{
			return reinterpret_cast<T>(m_ptr);
		}

		template<typename T>
		[[nodiscard]] std::enable_if_t<std::is_lvalue_reference_v<T>, T> as() const noexcept
		{
			return *reinterpret_cast<std::add_pointer_t<std::remove_reference_t<T>>>(m_ptr);
		}

		template<typename T>
		[[nodiscard]] std::enable_if_t<std::is_integral_v<T>, T> as() const noexcept
		{
			return static_cast<T>(reinterpret_cast<std::uintptr_t>(m_ptr));
		}

		template<typename T>
		[[nodiscard]] handle add(T offset) const noexcept
		{
			return handle(reinterpret_cast<std::uintptr_t>(m_ptr) + static_cast<std::uintptr_t>(offset));
		}

		template<typename T>
		[[nodiscard]] handle sub(T offset) const noexcept
		{
			return handle(reinterpret_cast<std::uintptr_t>(m_ptr) - static_cast<std::uintptr_t>(offset));
		}

		[[nodiscard]] handle rip() const noexcept
		{
			if (!m_ptr)
				return handle();
			return add(as<std::int32_t&>()).add(4);
		}

		[[nodiscard]] void* raw() const noexcept
		{
			return m_ptr;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return m_ptr != nullptr;
		}

		friend bool operator==(handle a, handle b) noexcept { return a.m_ptr == b.m_ptr; }
		friend bool operator!=(handle a, handle b) noexcept { return a.m_ptr != b.m_ptr; }
		friend bool operator<(handle a, handle b) noexcept  { return a.m_ptr < b.m_ptr; }
		friend bool operator>(handle a, handle b) noexcept  { return a.m_ptr > b.m_ptr; }
		friend bool operator<=(handle a, handle b) noexcept { return a.m_ptr <= b.m_ptr; }
		friend bool operator>=(handle a, handle b) noexcept { return a.m_ptr >= b.m_ptr; }

	private:
		void* m_ptr{nullptr};
	};
}
