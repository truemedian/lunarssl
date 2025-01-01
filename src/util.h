#pragma once

#include "vendor/compat-5.3.h"
#include <lauxlib.h>
#include <lua.h>

#ifndef unreachable
#if defined(__GNUC__) || defined(__clang__)
#define unreachable() __builtin_unreachable()
#elif defined(_MSC_VER)
#define unreachable() __assume(0)
#else
#define unreachable() ((void)0)
#endif
#endif

#define LUNARSSL_ENUM(name, value) { name, sizeof(name) - 1, value }
#define LUNARSSL_ENUM_END { NULL, 0, 0 }

#define LUNARSSL_ENUM_ALLOW_DEFAULT 0x01
#define LUNARSSL_ENUM_NO_INTEGER 0x02

typedef struct lunarssl_Enum {
    const char* name;
    int name_len;
    int value;
} lunarssl_Enum;

int lunarssl_checkenum(lua_State* L, int idx, int opt, const lunarssl_Enum* lst);

int lunarssl_isudata(lua_State* L, int idx, const char* mt);
void* lunarssl_toudata_(lua_State* L, int idx, const char* mt);
#define lunarssl_toudata(L, T, idx, mt) ((T*)lunarssl_toudata_((L), (idx), (mt)))
#define lunarssl_checkudata(L, T, idx, mt) ((T*)luaL_checkudata((L), (idx), (mt)))
#define lunarssl_newudata(L, T, mt)        \
    ((T*)lua_newuserdata((L), sizeof(T))); \
    luaL_setmetatable((L), (mt))
