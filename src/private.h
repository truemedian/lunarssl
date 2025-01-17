#pragma once

#define OPENSSL_API_COMPAT 0x10101000L
#define OPENSSL_NO_DEPRECATED 1

#include <lauxlib.h>
#include <limits.h>
#include <lua.h>
#include <stddef.h>

#define LUNAR_INTERNAL static
#define LUNAR_FUNCTION static
#define LUNAR_EXPORT extern

#if defined(__has_attribute)
#    define LUNAR_HAS_ATTRIBUTE(attr) __has_attribute(attr)
#else
#    define LUNAR_HAS_ATTRIBUTE(attr) 0
#endif

#if defined(__has_builtin)
#    define LUNAR_HAS_BUILTIN(builtin) __has_builtin(builtin)
#else
#    define LUNAR_HAS_BUILTIN(builtin) 0
#endif

#if LUNAR_HAS_ATTRIBUTE(noreturn)
#    define LUNAR_NORETURN __attribute__((noreturn))
#else
#    define LUNAR_NORETURN
#endif

#if LUNAR_HAS_BUILTIN(__builtin_expect)
#    define LUNAR_LIKELY(x) __builtin_expect(((x) != 0), 1)
#    define LUNAR_UNLIKELY(x) __builtin_expect(((x) != 0), 0)
#else
#    define LUNAR_LIKELY(x) (x)
#    define LUNAR_UNLIKELY(x) (x)
#endif

#if !defined(unreachable)
#    if defined(__GNUC__) || defined(__clang__)
#        define unreachable() __builtin_unreachable()
#    elif defined(_MSC_VER)
#        define unreachable() __assume(0)
#    else
#        define unreachable() ((void)0)
#    endif
#endif

#if !defined(LUA_MAXINTEGER)
#    define LUA_MAXINTEGER ((((lua_Integer)1 << (sizeof(lua_Integer) * CHAR_BIT - 2)) - 1) * 2 + 1)
#endif

/* The maximum size representable in both size_t and lua_Integer. */
#define LUNAR_MAXSIZE (LUA_MAXINTEGER > SIZE_MAX ? (lua_Integer)SIZE_MAX : LUA_MAXINTEGER)

/*! Raises an error. The error message is constructed using `luaL_where` and `lua_pushfstring`. */
LUNAR_EXPORT void LUNAR_NORETURN lunar_error(lua_State* const L, const char* const fmt, ...);

/*! Raises an error reporting a problem with argument arg of the C function that called it
 * using a standard message that includes fmt formatted as in `lua_pushfstring` as a comment:
 *     `bad argument #arg to 'funcname' (extramsg)`
 */
LUNAR_EXPORT void LUNAR_NORETURN lunar_argerror(lua_State* const L, int arg, const char* const fmt, ...);

/*! Raises an error reporting a problem with the type of argument arg of the C function that called it
 * and provides the expected type name tname and the actual type name of the argument (following __name if present):
 *     `bad argument #arg to 'funcname' (expected tname, got name)`
 */
LUNAR_EXPORT void LUNAR_NORETURN lunar_typeerror(lua_State* const L, int arg, const char* const tname);

#define lunar_argcheck(L, cond, arg, ...) \
    if (LUNAR_UNLIKELY(cond))             \
    lunar_argerror((L), (arg), __VA_ARGS__)
#define lunar_argexpected(L, cond, arg, tname) \
    if (LUNAR_UNLIKELY(cond))                  \
    lunar_typeerror((L), (arg), (tname))

LUNAR_EXPORT lua_Integer lunar_checkwithin(lua_State* const L, const int idx, const lua_Integer min, const lua_Integer max);
LUNAR_EXPORT lua_Integer lunar_optwithin(lua_State* const L, const int idx, const lua_Integer def, const lua_Integer min, const lua_Integer max);

#define lunar_checksize(L, idx) (size_t)lunar_checkwithin((L), (idx), 0, LUNAR_MAXSIZE)
#define lunar_optsize(L, idx, def) (size_t)lunar_optwithin((L), (idx), (def), 0, LUNAR_MAXSIZE)

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
    lua_setfield(L, -2, "__index")

#ifdef NDEBUG
#    define LUNAR_ENTER(n) ((void)0)
#    define LUNAR_LEAVE(n) return n
#else
#    define LUNAR_ENTER(n)                           \
        const int _lunar__stack_top = lua_gettop(L); \
        if ((n) > 0 && _lunar__stack_top < (n))      \
        lunar_argerror(L, n, "expected at least %d arguments, got %d", n, _lunar__stack_top)

#    define LUNAR_LEAVE(n)                                    \
        do {                                                  \
            assert(_lunar__stack_top + (n) == lua_gettop(L)); \
            return n;                                         \
        } while (0)
#endif

#define LUNAR_EMPTY \
    do {            \
    } while (0)

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
    }                                                                    \
    LUNAR_EMPTY

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
    }                                                                    \
    LUNAR_EMPTY

/*! Calls `fn` and throws a Lua error with information when `check` evaluates to false.
 *  This macro is designed to be used as the right hand side of an assignment.
 */
#define LUNAR_DCALL(check, fn, ...) LUNAR_DCALLF(check, {}, fn, __VA_ARGS__)

/*                  Lunar functions aimed directly at OpenSSL                 */

/*! [-0, +1, m] Returns the current list of openssl errors as a `;` separated list of errors.
 *  Clears the openssl error stack.
 */
LUNAR_EXPORT const char* lunarssl_collect_errorlist(lua_State* const L);
