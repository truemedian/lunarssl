#include "private.h"

#include "compat.h"

#include <lua.h>

#if LUA_VERSION_NUM <= 501

LUNAR_EXPORT int lua_isinteger(lua_State* const L, const int idx) {
    if (!lua_isnumber(L, idx))
        return 0;

    lua_Integer i = lua_tointeger(L, idx);
    if (i == 0) {// either not valid or zero
        lua_Number n = lua_tonumber(L, idx);
        return n >= 0.0 && n <= 0.0; // 0 is a valid integer
    } else
        return 1; // any non-zero means we have a valid integer
}

#endif
