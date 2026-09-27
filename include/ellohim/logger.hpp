#pragma once
#include <string_view>
#include <format>
#include <functional>
#include <iostream>

namespace ellohim
{
	enum class log_level
	{
		info,
		warning,
		error,
		fatal
	};

	using log_callback_t = std::function<void(log_level level, std::string_view msg)>;

	class logger
	{
	public:
		static void set_callback(log_callback_t callback);
		static void log(log_level level, std::string_view msg);

		template<typename... Args>
		static void info(std::format_string<Args...> fmt, Args&&... args)
		{
			log(log_level::info, std::format(fmt, std::forward<Args>(args)...));
		}

		template<typename... Args>
		static void warning(std::format_string<Args...> fmt, Args&&... args)
		{
			log(log_level::warning, std::format(fmt, std::forward<Args>(args)...));
		}

		template<typename... Args>
		static void error(std::format_string<Args...> fmt, Args&&... args)
		{
			log(log_level::error, std::format(fmt, std::forward<Args>(args)...));
		}

		template<typename... Args>
		static void fatal(std::format_string<Args...> fmt, Args&&... args)
		{
			log(log_level::fatal, std::format(fmt, std::forward<Args>(args)...));
		}
	};
}
