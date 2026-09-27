#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

namespace ellohim::core
{
	class thread_freezer
	{
	public:
		thread_freezer()
		{
			const DWORD current_pid = GetCurrentProcessId();
			const DWORD current_tid = GetCurrentThreadId();

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snapshot == INVALID_HANDLE_VALUE)
				return;

			THREADENTRY32 te{};
			te.dwSize = sizeof(te);

			if (Thread32First(snapshot, &te))
			{
				do
				{
					if (te.th32OwnerProcessID == current_pid && te.th32ThreadID != current_tid)
					{
						HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
						if (thread)
						{
							SuspendThread(thread);
							m_threads.push_back(thread);
						}
					}
				} while (Thread32Next(snapshot, &te));
			}

			CloseHandle(snapshot);
		}

		~thread_freezer()
		{
			for (HANDLE thread : m_threads)
			{
				ResumeThread(thread);
				CloseHandle(thread);
			}
		}

		thread_freezer(const thread_freezer&) = delete;
		thread_freezer& operator=(const thread_freezer&) = delete;

	private:
		std::vector<HANDLE> m_threads;
	};
}
