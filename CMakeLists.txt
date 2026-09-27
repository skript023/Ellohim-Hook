set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
cmake_minimum_required(VERSION 3.20)

project(EllohimHook LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/permissive- /bigobj)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()

# Core disassembler source depending on architecture
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(HDE_SRC src/hooking/core/hde/hde64.c)
else()
    set(HDE_SRC src/hooking/core/hde/hde32.c)
endif()

# Library sources
set(ELLOHIM_HOOK_SOURCES
    ${HDE_SRC}
    src/logger.cpp
    src/memory/pattern.cpp
    src/memory/range.cpp
    src/memory/module.cpp
    src/hooking/core/buffer.cpp
    src/hooking/core/trampoline.cpp
    src/hooking/detour_base.cpp
    src/hooking/detour_hook.cpp
    src/hooking/vmt_hook.cpp
    src/hooking/swap_pointer_hook.cpp
    src/hooking/mid_hook.cpp
    src/hooking.cpp
)

# Header files for IDE navigation
set(ELLOHIM_HOOK_HEADERS
    include/ellohim/common.hpp
    include/ellohim/logger.hpp
    include/ellohim/hooking.hpp
    include/ellohim/ellohim.hpp
    include/ellohim/memory/handle.hpp
    include/ellohim/memory/range.hpp
    include/ellohim/memory/module.hpp
    include/ellohim/memory/pattern.hpp
    include/ellohim/hooking/detour_base.hpp
    include/ellohim/hooking/detour_hook.hpp
    include/ellohim/hooking/vmt_hook.hpp
    include/ellohim/hooking/swap_pointer_hook.hpp
    include/ellohim/hooking/mid_hook.hpp
    src/hooking/core/buffer.hpp
    src/hooking/core/trampoline.hpp
    src/hooking/core/thread_freezer.hpp
)

add_library(EllohimHook STATIC ${ELLOHIM_HOOK_SOURCES} ${ELLOHIM_HOOK_HEADERS})

target_include_directories(EllohimHook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(EllohimHook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hooking
)

# Examples and test demo
option(ELLOHIM_BUILD_EXAMPLES "Build Ellohim-Hook example executable" ON)

if (ELLOHIM_BUILD_EXAMPLES)
    add_executable(EllohimHookExample examples/main.cpp)
    target_link_libraries(EllohimHookExample PRIVATE EllohimHook user32)
    set_target_properties(EllohimHookExample PROPERTIES CXX_STANDARD 20)
endif()
