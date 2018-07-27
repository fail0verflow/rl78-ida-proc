#pragma once

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Quiet useless warnings from hex-rays headers
#define NO_OBSOLETE_FUNCS

// ...
#pragma warning(push)
#pragma warning(disable : 4244; disable : 4267)

#include <frame.hpp>
#include <idp.hpp>
#include <idaidp.hpp>
#include <segregs.hpp>

#pragma warning(pop)

#undef NO_OBSOLETE_FUNCS
