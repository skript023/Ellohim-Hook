#include <ellohim/hooking/detour_hook.hpp>
#include <string>

static std::string failure;
static bool teleportable(void*, bool)
{
	return true;
}

extern "C" __declspec(dllexport) const char* test_mono_hook(void* target)
{
	try
	{
		ellohim::logger::set_callback([](auto, auto) {
		});
		for (int i = 0; i < 3; ++i)
		{
			ellohim::detour_hook hook("Mono Inventory.IsTeleportable", target, reinterpret_cast<void*>(&teleportable));
			hook.enable();
			if (!reinterpret_cast<bool (*)(void*, bool)>(target)(nullptr, false))
				throw std::runtime_error("Mono detour did not execute");
			if (!hook.disable())
				throw std::runtime_error("Mono detour did not restore");
		}
		return nullptr;
	}
	catch (const std::exception& error)
	{
		failure = error.what();
		return failure.c_str();
	}
}
