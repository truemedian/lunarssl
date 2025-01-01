#include "util.h"

int lunarssl_checkenum(lua_State* L, int idx, int opt, const lunarssl_Enum* lst) {
    int typ = lua_type(L, idx);

    switch (typ) {
    case LUA_TNONE:
    case LUA_TNIL:
        if (opt & LUNARSSL_ENUM_ALLOW_DEFAULT) {
            return lst->value;
        }
    case LUA_TNUMBER:
        if (opt & LUNARSSL_ENUM_NO_INTEGER) {
            return luaL_typeerror(L, idx, "string");
        }

        lua_Integer v = luaL_checkinteger(L, idx);
        for (const lunarssl_Enum* e = lst; e->name; e++) {
            if (e->value == v) {
                return v;
            }
        }

        return luaL_argerror(L, idx, "invalid enumeration value");
    case LUA_TSTRING:
        size_t len;
        const char* str = lua_tolstring(L, idx, &len);
        for (const lunarssl_Enum* e = lst; e->name; e++) {
            if (e->name_len == len && memcmp(e->name, str, len) == 0) {
                return e->value;
            }
        }

        return luaL_argerror(L, idx, "invalid enumeration string");
    }

    if (opt & LUNARSSL_ENUM_NO_INTEGER) {
        return luaL_typeerror(L, idx, "string");
    } else {
        return luaL_typeerror(L, idx, "string or integer");
    }
}

int lunarssl_isudata(lua_State* L, int idx, const char* mt) {
    if (!lua_isuserdata(L, idx)) {
        return 0;
    }

    if (lua_getmetatable(L, idx)) {
        lua_getfield(L, LUA_REGISTRYINDEX, mt);
        if (lua_rawequal(L, -1, -2)) {
            lua_pop(L, 2);
            return 1;
        }
        lua_pop(L, 2);
    }

    return 0;
}

void* lunarssl_toudata_(lua_State* L, int idx, const char* mt) {
    if (!lunarssl_isuserdata(L, idx, mt)) {
        return NULL;
    }

    return lua_touserdata(L, idx);
}