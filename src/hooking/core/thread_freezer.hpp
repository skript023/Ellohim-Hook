#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <stdexcept>
#include "trampoline.hpp"
namespace ellohim::core
{
	class thread_freezer
	{
		struct entry
		{
			HANDLE handle;
			bool suspended{};
			CONTEXT context{};
			bool changed{};
		};
		std::vector<entry> m_threads;

	public:
		thread_freezer()
		{
			const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snapshot == INVALID_HANDLE_VALUE)
				throw std::runtime_error("Thread enumeration failed");
			THREADENTRY32 te{};
			te.dwSize = sizeof(te);
			bool failed = false;
			if (!Thread32First(snapshot, &te))
				failed = true;
			else
				do
				{
					if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
						continue;
					const auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
					if (!thread)
					{
						if (GetLastError() != ERROR_INVALID_PARAMETER)
							failed = true;
						continue;
					}
					try
					{
						m_threads.push_back({thread});
					}
					catch (...)
					{
						CloseHandle(thread);
						CloseHandle(snapshot);
						release();
						throw;
					}
				} while (Thread32Next(snapshot, &te));
			CloseHandle(snapshot);
			if (failed)
			{
				release();
				throw std::runtime_error("Could not open all process threads for patching");
			}
			// All storage is allocated before suspending a thread that might hold the heap lock.
			for (auto& thread : m_threads)
			{
				if (SuspendThread(thread.handle) == DWORD(-1))
				{
					DWORD code{};
					if (GetExitCodeThread(thread.handle, &code) && code != STILL_ACTIVE)
						continue;
					failed = true;
					break;
				}
				thread.suspended = true;
				thread.context.ContextFlags = CONTEXT_CONTROL;
				if (!GetThreadContext(thread.handle, &thread.context))
				{
					failed = true;
					break;
				}
			}
			if (failed)
			{
				release();
				throw std::runtime_error("Could not suspend/read all thread contexts");
			}
		}
		~thread_freezer()
		{
			release();
		}
		void release() noexcept
		{
			for (auto& thread : m_threads)
				if (thread.suspended)
				{
					ResumeThread(thread.handle);
					thread.suspended = false;
				}
			for (auto& thread : m_threads)
				CloseHandle(thread.handle);
			m_threads.clear();
		}
		bool relocate(const hook_info& info, bool enabling)
		{
			const auto target = reinterpret_cast<uintptr_t>(info.target);
			const auto trampoline = reinterpret_cast<uintptr_t>(info.trampoline);
			for (auto& thread : m_threads)
			{
				if (!thread.suspended)
					continue;
				auto& ip = thread.context.Rip;
				bool mapped = false;
				for (uint32_t i = 0; i < info.count; ++i)
				{
					const auto from = enabling ? target + info.old_offsets[i] : trampoline + info.new_offsets[i];
					if (ip == from)
					{
						ip = enabling ? trampoline + info.new_offsets[i] : target + info.old_offsets[i];
						mapped = true;
						break;
					}
				}
				if (!enabling && ip == trampoline + info.trampoline_size - 14)
				{
					ip = target + info.stolen_size;
					mapped = true;
				}
				if (!enabling && info.relay && ip == reinterpret_cast<uintptr_t>(info.relay))
				{
					ip = target;
					mapped = true;
				}
				if (!mapped && ((enabling && ip >= target && ip < target + info.patch_size) || (!enabling && ip >= trampoline && ip < trampoline + info.trampoline_size)))
					return false;
				thread.changed = mapped;
			}
			for (auto& thread : m_threads)
				if (thread.changed && !SetThreadContext(thread.handle, &thread.context))
					return false;
			return true;
		}
		thread_freezer(const thread_freezer&) = delete;
		thread_freezer& operator=(const thread_freezer&) = delete;
	};
}
