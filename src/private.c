#include "private.h"

#include <lauxlib.h>
#include <lua.h>
#include <openssl/err.h>
#include <stddef.h>
#include <stdio.h>

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
    if (ERR_peek_error() == 0)
        return lua_pushstring(L, "no error reported");

    const int top = lua_gettop(L);
    for (unsigned long err = ERR_get_error(); err != 0; err = ERR_get_error()) {
        const int library_n = ERR_GET_LIB(err);
        const int reason_n = ERR_GET_REASON(err);

        const char* const library = ERR_lib_error_string(err);
        const char* const reason = ERR_reason_error_string(err);

        char err_s[(sizeof(err) * 2) + 1] = { 0 };
        snprintf(err_s, sizeof(err_s), "%lx", err);

        char library_s[(sizeof(library_n) * 2) + 1] = { 0 };
        snprintf(library_s, sizeof(library_s), "%x", library_n);

        char reason_s[(sizeof(reason_n) * 2) + 1] = { 0 };
        snprintf(reason_s, sizeof(reason_s), "%x", reason_n);

        luaL_checkstack(L, 2, NULL);
        lua_pushfstring(L, "%s:%s::%s", err_s, library ? library : library_s, reason ? reason : reason_s);
        lua_pushstring(L, "; ");
    }

    lua_pop(L, 1);
    lua_concat(L, lua_gettop(L) - top);
    return lua_tostring(L, -1);
}
