#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <format>
#include <stdexcept>
#include <type_traits>
#include <algorithm>
#include <functional>
#include <optional>
#include <span>

#include "logger.hpp"
