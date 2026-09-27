#include "ellohim/logger.hpp"
#include <mutex>
#include <iostream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace ellohim
{
	static std::mutex g_log_mutex;
	static log_callback_t g_log_callback;

	void logger::set_callback(log_callback_t callback)
	{
		std::lock_guard lock(g_log_mutex);
		g_log_callback = std::move(callback);
	}

	void logger::log(log_level level, std::string_view msg)
	{
		std::lock_guard lock(g_log_mutex);
		if (g_log_callback)
		{
			g_log_callback(level, msg);
			return;
		}

		const char* tag = "[INFO]";
		switch (level)
		{
		case log_level::info:    tag = "[INFO]"; break;
		case log_level::warning: tag = "[WARN]"; break;
		case log_level::error:   tag = "[ERROR]"; break;
		case log_level::fatal:   tag = "[FATAL]"; break;
		}

		std::string formatted = std::format("[Ellohim-Hook]{} {}\n", tag, msg);
		std::cout << formatted;
		OutputDebugStringA(formatted.c_str());
	}
}
