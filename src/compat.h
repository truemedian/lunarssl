#pragma once

#include "private.h"

#include <lua.h>

#if LUA_VERSION_NUM <= 501

LUNAR_EXPORT int lua_isinteger(lua_State* const L, const int idx);

#endif
