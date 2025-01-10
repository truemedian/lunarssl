#pragma once

#define OPENSSL_API_COMPAT 0x10101000L
#define OPENSSL_NO_DEPRECATED 1

#include "vendor/compat-5.3.h"

#include <lauxlib.h>
#include <lua.h>
#include <stddef.h>

#define LUNAR_INTERNAL static
#define LUNAR_FUNCTION static
#define LUNAR_EXPORT extern

#ifndef unreachable
#if defined(__GNUC__) || defined(__clang__)
#define unreachable() __builtin_unreachable()
#elif defined(_MSC_VER)
#define unreachable() __assume(0)
#else
#define unreachable() ((void)0)
#endif
#endif

/*! Create a new instance of class `name` (which is a `T`) and return a pointer to it.
 * @tparam T typename of the class
 * @param name name of class metatable
 * @return `T*`
 */
#define lunar_class_create(T, name) (T*)lunar_class_create0(L, (name), sizeof(T))

/*! Check that argument `idx` is an instance of class `name` (which is a `T`) and return a pointer to it.
 *
 *  Throws an error if argument `idx` is not an instance of class `name`.
 * @tparam T typename of the class
 * @param idx argument index
 * @param name name of class metatable
 * @return `T*`
 */
#define lunar_class_check(T, idx, name) (T*)luaL_checkudata(L, (idx), (name))

/*! Check that argument `idx` is an instance of class `name` (which is a `T`) and return a pointer to it.
 *
 *  Returns NULL if argument `idx` is not an instance of class `name`.
 * @tparam T typename of the class
 * @param idx argument index
 * @param name name of class metatable
 * @return `T*` or `NULL`
 */
#define lunar_class(T, idx, name) lunar_class0(L, (idx), (name))

LUNAR_EXPORT void* lunar_class_create0(lua_State* const L, const char* const name, const size_t len);
LUNAR_EXPORT void* lunar_class0(lua_State* const L, const int idx, const char* const name);

#define lunar_register_library(reg) luaL_newlib(L, (reg))
#define lunar_register_append(reg) luaL_setfuncs(L, (reg), 0)

#define lunar_register_class(name) \
    luaL_newmetatable(L, (name));  \
    lua_pushstring(L, (name));     \
    lua_setfield(L, -2, "__name"); \
    lua_pushvalue(L, -1);          \
    lua_setfield(L, -2, "__index");

#ifdef NDEBUG
#define LUNAR_ENTER(n) ((void)0)
#define LUNAR_LEAVE(n) return n
#else
#define LUNAR_ENTER(n)                                                                                      \
    const int __stack_top = lua_gettop(L);                                                                  \
    if ((n) > 0 && __stack_top < (n)) {                                                                     \
        const char* const f = lua_pushfstring(L, "expected at least %d arguments, got %d", n, __stack_top); \
        luaL_argerror(L, n, f);                                                                             \
        unreachable();                                                                                      \
    }
#define LUNAR_LEAVE(n)                              \
    do {                                            \
        assert(__stack_top + (n) == lua_gettop(L)); \
        return n;                                   \
    } while (0)
#endif

#define LUNAR_THROW(errf, ...)  \
    do {                        \
        errf((L), __VA_ARGS__); \
        unreachable();          \
    } while (0)

/*! Calls `fn` and throws a Lua error with information when its return value evaluates to false.
 *  The `finally` expression is run regardless of whether `fn` succeeds or fails.
 *  The `free` expression is only run when `fn` fails.
 */
#define LUNAR_FCALLF(finally, free, fn, ...)                                 \
    do {                                                                     \
        if (!fn(__VA_ARGS__)) {                                              \
            free;                                                            \
            finally;                                                         \
            luaL_error(L, #fn " failed: %s", lunarssl_collect_errorlist(L)); \
            unreachable();                                                   \
        }                                                                    \
        finally;                                                             \
    } while (0)

/*! Calls `fn` and throws a Lua error with information when its return value evaluates to false.
 *  The `finally` expression is run regardless of whether `fn` succeeds or fails.
 */
#define LUNAR_FCALL(finally, fn, ...) LUNAR_FCALLF(finally, {}, fn, __VA_ARGS__)

/*! Calls `fn` and throws a Lua error with information when its return value evaluates to false.
 *  The `free` expression is only run when `fn` fails.
 */
#define LUNAR_TCALLF(free, fn, ...) LUNAR_FCALLF({}, free, fn, __VA_ARGS__)

/*! Calls `fn` and throws a Lua error with information when its return value evaluates to false.
 */
#define LUNAR_TCALL(fn, ...) LUNAR_TCALLF({}, fn, __VA_ARGS__)

/*! Calls `fn` with 0 arguments and throws a Lua error with information when `check` evaluates to false.
 *  This macro is designed to be used as the right hand side of an assignment.
 *  The `free` expression is only run when `fn` fails.
 */
#define LUNAR_DCALLF0(check, free, fn)                                   \
    fn();                                                                \
    if (!(check)) {                                                      \
        free;                                                            \
        luaL_error(L, #fn " failed: %s", lunarssl_collect_errorlist(L)); \
        unreachable();                                                   \
    }

/*! Calls `fn` with 0 arguments and throws a Lua error with information when `check` evaluates to false.
 *  This macro is designed to be used as the right hand side of an assignment.
 */
#define LUNAR_DCALL0(check, fn) LUNAR_DCALLF0(check, {}, fn)

/*! Calls `fn` and throws a Lua error with information when `check` evaluates to false.
 *  This macro is designed to be used as the right hand side of an assignment.
 *  The `free` expression is only run when `fn` fails.
 */
#define LUNAR_DCALLF(check, free, fn, ...)                               \
    fn(__VA_ARGS__);                                                     \
    if (!(check)) {                                                      \
        free;                                                            \
        luaL_error(L, #fn " failed: %s", lunarssl_collect_errorlist(L)); \
        unreachable();                                                   \
    }

/*! Calls `fn` and throws a Lua error with information when `check` evaluates to false.
 *  This macro is designed to be used as the right hand side of an assignment.
 */
#define LUNAR_DCALL(check, fn, ...) LUNAR_DCALLF(check, {}, fn, __VA_ARGS__)

/*                  Lunar functions aimed directly at OpenSSL                 */

/*! [-0, +1, m] Returns the current list of openssl errors as a `;` separated list of errors.
 *  Clears the openssl error stack.
 */
LUNAR_EXPORT const char* lunarssl_collect_errorlist(lua_State* const L);
