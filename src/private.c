#include "private.h"

#include <lauxlib.h>
#include <lua.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

LUNAR_EXPORT void LUNAR_NORETURN lunar_error(lua_State* const L, const char* const fmt, ...) {
    va_list argp;
    va_start(argp, fmt);

    luaL_where(L, 1);
    lua_pushvfstring(L, fmt, argp);
    va_end(argp);

    lua_concat(L, 2);
    lua_error(L);
    unreachable();
}

LUNAR_EXPORT void LUNAR_NORETURN lunar_argerror(lua_State* const L, int arg, const char* const fmt, ...) {
    va_list argp;
    va_start(argp, fmt);

    const char* const extramsg = lua_pushvfstring(L, fmt, argp);
    va_end(argp);

    lua_Debug ar; // no stack frame
    if (!lua_getstack(L, 0, &ar))
        lunar_error(L, "bad argument #%d (%s)", arg, extramsg);

    lua_getinfo(L, "n", &ar);
    if (strcmp(ar.namewhat, "method") == 0) {
        arg -= 1; // don't count implicit self
        if (arg == 0) // error is in the self argument
            lunar_error(L, "calling '%s' on bad self (%s)", ar.name, extramsg);
    }

    if (ar.name == NULL)
        ar.name = "?";

    lunar_error(L, "bad argument #%d to '%s' (%s)", arg, ar.name, extramsg);
}

LUNAR_EXPORT void LUNAR_NORETURN lunar_typeerror(lua_State* const L, int arg, const char* const tname) {
    if (luaL_getmetafield(L, arg, "__name")) {
        if (lua_type(L, -1) == LUA_TSTRING) {
            const char* const name = lua_tostring(L, -1);
            lunar_argerror(L, arg, "expected %s, got %s", tname, name);
        }

        lua_pop(L, 1);
    }

    const char* const name = luaL_typename(L, arg);
    lunar_argerror(L, arg, "expected %s, got %s", tname, name);
}

LUNAR_EXPORT lua_Integer lunar_checkwithin(lua_State* const L, const int idx, const lua_Integer min, const lua_Integer max) {
    const lua_Integer r = luaL_checkinteger(L, idx);
    if (r < min || r > max)
        lunar_argerror(L, idx, "out of range [%d, %d]", min, max);

    return r;
}

LUNAR_EXPORT lua_Integer lunar_optwithin(lua_State* const L, const int idx, const lua_Integer def, const lua_Integer min, const lua_Integer max) {
    const lua_Integer r = luaL_optinteger(L, idx, def);
    if (r < min || r > max)
        lunar_argerror(L, idx, "out of range [%d, %d]", min, max);

    return r;
}

LUNAR_EXPORT void* lunar_class_create0(lua_State* const L, const char* const name, const size_t len) {
#if LUA_VERSION_NUM >= 504
    void* const r = lua_newuserdatauv(L, len, 0);
#else
    void* const r = lua_newuserdata(L, len);
#endif

    luaL_setmetatable(L, name);
    return r;
}

LUNAR_EXPORT void* lunar_class0(lua_State* const L, const int idx, const char* const name) {
    if (!lua_isuserdata(L, idx))
        return NULL;

    if (lua_getmetatable(L, idx)) {
        luaL_getmetatable(L, name);

        const int eq = lua_rawequal(L, -1, -2);
        lua_pop(L, 2);

        return eq ? lua_touserdata(L, idx) : NULL;
    }

    return NULL;
}

/*                  Lunar functions aimed directly at OpenSSL                 */

LUNAR_EXPORT const char* lunarssl_collect_errorlist(lua_State* const L) {
    if (ERR_peek_error() == 0) {
        lua_pushstring(L, "no error reported");
    } else {
        const int top = lua_gettop(L);
        for (unsigned long err = ERR_get_error(); err != 0; err = ERR_get_error()) {
            char buf[256];

            ERR_error_string_n(err, buf, sizeof(buf));

            luaL_checkstack(L, 2, NULL);
            lua_pushstring(L, buf);
            lua_pushstring(L, "; ");
        }

        lua_pop(L, 1);
        lua_concat(L, lua_gettop(L) - top);
    }

    return lua_tostring(L, -1);
}
