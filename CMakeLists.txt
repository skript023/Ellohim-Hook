set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
cmake_minimum_required(VERSION 3.20)

project(EllohimHook LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This hardened integration currently supports Windows x64 only")
endif()

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
option(ELLOHIM_BUILD_EXAMPLES "Build Ellohim-Hook example executable" OFF)

option(ELLOHIM_BUILD_TESTS "Build native hook regression tests" OFF)
if(ELLOHIM_BUILD_TESTS)
    enable_testing()
    add_executable(ellohim_hook_tests tests/hooks.cpp)
    add_library(ellohim_mono_bridge SHARED tests/mono_bridge.cpp)
    target_link_libraries(ellohim_mono_bridge PRIVATE EllohimHook)
    set_target_properties(ellohim_mono_bridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/hook-tests" LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/hook-tests")
    target_link_libraries(ellohim_hook_tests PRIVATE EllohimHook)
    target_include_directories(ellohim_hook_tests PRIVATE src/hooking)
    set_target_properties(ellohim_hook_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/hook-tests")
    add_test(NAME ellohim_hooks COMMAND ellohim_hook_tests)
    set_tests_properties(ellohim_hooks PROPERTIES TIMEOUT 30)
endif()

if (ELLOHIM_BUILD_EXAMPLES)
    add_executable(EllohimHookExample examples/main.cpp)
    target_link_libraries(EllohimHookExample PRIVATE EllohimHook user32)
    set_target_properties(EllohimHookExample PROPERTIES CXX_STANDARD 20)
endif()
