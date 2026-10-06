#include "ellohim/hooking/mid_hook.hpp"
#include "core/buffer.hpp"
#include <cstring>
namespace ellohim
{
	mid_hook::mid_hook(std::string_view name, void* target, mid_callback_t callback) :
	    m_name(name),
	    m_target(target),
	    m_callback(callback)
	{
		if (!target || !callback)
			throw std::runtime_error("Null mid-hook target/callback");
		try
		{
			build_stub();
		}
		catch (...)
		{
			m_backend.reset();
			core::free_page_near(m_stub, m_stub_size);
			throw;
		}
	}
	mid_hook::~mid_hook() noexcept
	{
		std::erase(m_mid_hooks, this);
		if (!disable())
		{
			m_backend.release();
			return;
		}
		m_backend.reset();
		core::free_page_near(m_stub, m_stub_size);
	}
	void mid_hook::fix_hook_address()
	{
	}
	void mid_hook::build_stub()
	{
		static_assert(sizeof(mid_context) == 400 && offsetof(mid_context, rax) == 376 && offsetof(mid_context, rip) == 392);
		m_stub_size = 4096;
		m_stub = VirtualAlloc(nullptr, m_stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!m_stub)
			throw std::runtime_error("Could not allocate mid-hook stub");
		m_backend = std::make_unique<detour_hook>(m_name, m_target, m_stub, false);
		std::vector<uint8_t> code;
		auto bytes = [&](std::initializer_list<uint8_t> list) {
			code.insert(code.end(), list);
		};
		auto dword = [&](uint32_t value) {
			for (int i = 0; i < 4; ++i)
				code.push_back(static_cast<uint8_t>(value >> (i * 8)));
		};
		auto qword = [&](uint64_t value) {
			dword(static_cast<uint32_t>(value));
			dword(static_cast<uint32_t>(value >> 32));
		};
		// Reserve RIP without destroying a live register; save flags before any arithmetic.
		bytes({0x50, 0x9c, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55});
		for (uint8_t i = 0; i < 8; ++i)
			bytes({0x41, static_cast<uint8_t>(0x50 + i)});
		bytes({0x48, 0x8d, 0x84, 0x24});
		dword(136);
		bytes({0x50});
		bytes({0x48, 0x81, 0xec});
		dword(256);
		for (uint32_t i = 0; i < 16; ++i)
		{
			bytes({0xf3});
			if (i >= 8)
				bytes({0x44});
			bytes({0x0f, 0x7f, static_cast<uint8_t>(0x84 | ((i % 8) << 3)), 0x24});
			dword(i * 16);
		}
		bytes({0x48, 0xb8});
		qword(reinterpret_cast<uintptr_t>(m_target));
		bytes({0x48, 0x89, 0x84, 0x24});
		dword(392);
		// RBX anchors the saved context across a dynamically aligned Win64 callback frame.
		bytes({0x48, 0x89, 0xe3, 0x48, 0x89, 0xe1, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20});
		bytes({0x48, 0xb8});
		qword(reinterpret_cast<uintptr_t>(m_callback));
		bytes({0xff, 0xd0, 0x48, 0x89, 0xdc});
		for (uint32_t i = 0; i < 16; ++i)
		{
			bytes({0xf3});
			if (i >= 8)
				bytes({0x44});
			bytes({0x0f, 0x6f, static_cast<uint8_t>(0x84 | ((i % 8) << 3)), 0x24});
			dword(i * 16);
		}
		bytes({0x48, 0x81, 0xc4});
		dword(264);
		for (int i = 7; i >= 0; --i)
			bytes({0x41, static_cast<uint8_t>(0x58 + i)});
		bytes({0x5d, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x9d});
		// LEA preserves the restored flags, unlike ADD RSP, 8.
		bytes({0x48, 0x8d, 0x64, 0x24, 8, 0xff, 0x25, 0, 0, 0, 0});
		qword(reinterpret_cast<uintptr_t>(m_backend->get_original_ptr()));
		if (code.size() > m_stub_size)
			throw std::runtime_error("Mid-hook stub overflow");
		std::memcpy(m_stub, code.data(), code.size());
		DWORD previous{};
		if (!VirtualProtect(m_stub, m_stub_size, PAGE_EXECUTE_READ, &previous) ||
		    !FlushInstructionCache(GetCurrentProcess(), m_stub, code.size()))
			throw std::runtime_error("Could not seal mid-hook stub");
	}
	bool mid_hook::enable()
	{
		if (m_enabled)
			return true;
		m_enabled = m_backend->enable();
		return m_enabled;
	}
	bool mid_hook::disable()
	{
		if (!m_enabled)
			return true;
		if (!m_backend->disable())
			return false;
		m_enabled = false;
		return true;
	}
	bool mid_hook::enable_all()
	{
		std::vector<mid_hook*> activated;
		activated.reserve(m_mid_hooks.size());
		try
		{
			for (auto hook : m_mid_hooks)
			{
				if (hook->is_enabled()) continue;
				activated.push_back(hook);
				if (!hook->enable()) throw std::runtime_error("Mid-hook enable failed");
			}
		}
		catch (...)
		{
			bool restored = true;
			for (auto it = activated.rbegin(); it != activated.rend(); ++it)
				restored = (*it)->disable() && restored;
			if (!restored) throw std::runtime_error("Mid-hook rollback failed");
			throw;
		}
		return true;
	}
	bool mid_hook::disable_all()
	{
		bool result = true;
		for (auto it = m_mid_hooks.rbegin(); it != m_mid_hooks.rend(); ++it)
			result = (*it)->disable() && result;
		return result;
	}
	bool mid_hook::any_enabled()
	{
		return std::any_of(m_mid_hooks.begin(), m_mid_hooks.end(), [](auto* hook) { return hook->is_enabled(); });
	}
	bool mid_hook::destroy_owned()
	{
		bool result = true;
		for (size_t i = m_mid_hooks.size(); i > 0; --i)
		{
			auto* hook = m_mid_hooks[i - 1];
			if (!hook->disable()) { result = false; continue; }
			delete hook;
		}
		return result;
	}
}
