#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <optional>
#include "handle.hpp"

namespace memory
{
	class pattern;

	class range
	{
	public:
		range(handle base, std::size_t size) noexcept;

		[[nodiscard]] handle begin() const noexcept;
		[[nodiscard]] handle end() const noexcept;
		[[nodiscard]] std::size_t size() const noexcept;

		[[nodiscard]] bool contains(handle h) const noexcept;

		[[nodiscard]] handle scan(const pattern& sig) const;
		[[nodiscard]] std::vector<handle> scan_all(const pattern& sig) const;

	protected:
		handle m_base{nullptr};
		std::size_t m_size{0};
	};
}
