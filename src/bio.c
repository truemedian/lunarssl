/// @module lunarssl.bio
#include "compat.h"
#include "private.h"

#include "bio.h"

#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <stddef.h>
#include <limits.h>

/// @function new_mem
/// Creates a new source/sink BIO backed by memory.
/// @tparam[opt] integer|string initial initial size or initial data
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_mem(lua_State* const L) {
    LUNAR_ENTER(0);

    BIO** const bio = lunar_class_create(BIO*, "lunarssl.bio");
    *bio = LUNAR_DCALL(*bio, BIO_new, BIO_s_mem());

    if (lua_isinteger(L, 1)) {
        const long n = lunar_checkwithin(L, 1, 0, LONG_MAX);

        LUNAR_TCALLF({ BIO_free(*bio); }, BIO_set_buffer_size, *bio, n);
    } else if (lua_isstring(L, 1)) {
        size_t len;
        const char* const str = lua_tolstring(L, 1, &len);
        luaL_argcheck(L, len <= INT_MAX, 1, "string too long");

        LUNAR_TCALLF({ BIO_free(*bio); }, BIO_write, *bio, str, (int)len);
    } else if (!lua_isnone(L, 1)) {
        lunar_typeerror(L, 1, "integer or string or nil");
        unreachable();
    }

    LUNAR_LEAVE(1);
}

/// @function new_secmem
/// Creates a new source/sink BIO backed by secure memory.
/// @tparam[opt] integer|string initial initial size or initial data
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_secmem(lua_State* const L) {
    LUNAR_ENTER(0);

    BIO** const bio = lunar_class_create(BIO*, "lunarssl.bio");
    *bio = LUNAR_DCALL(*bio, BIO_new, BIO_s_secmem());

    if (lua_isinteger(L, 1)) {
        const long n = lunar_checkwithin(L, 1, 0, LONG_MAX);

        LUNAR_TCALLF({ BIO_free(*bio); }, BIO_set_buffer_size, *bio, n);
    } else if (lua_isstring(L, 1)) {
        size_t len;
        const char* const str = lua_tolstring(L, 1, &len);
        lunar_argcheck(L, len <= INT_MAX, 1, "string too long");

        LUNAR_TCALLF({ BIO_free(*bio); }, BIO_write, *bio, str, (int)len);
    } else if (!lua_isnone(L, 1)) {
        lunar_typeerror(L, 1, "integer or string or nil");
    }

    LUNAR_LEAVE(1);
}

/// @function new_null
/// Creates a new null source/sink BIO. All data written is discarded and all reads return EOF.
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_null(lua_State* const L) {
    LUNAR_ENTER(0);

    BIO** const bio = lunar_class_create(BIO*, "lunarssl.bio");
    *bio = LUNAR_DCALL(*bio, BIO_new, BIO_s_null());

    LUNAR_LEAVE(1);
}

/// @function new_fd
/// Creates a new source/sink BIO backed by a file descriptor.
/// @tparam integer fd
/// @tparam[opt] boolean close_on_free
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_fd(lua_State* const L) {
    LUNAR_ENTER(1);

    const int fd = (int)lunar_checkwithin(L, 1, INT_MIN, INT_MAX);
    const int close_on_free = lua_toboolean(L, 2);

    BIO** const bio = lunar_class_create(BIO*, "lunarssl.bio");
    *bio = LUNAR_DCALL(*bio, BIO_new_fd, fd, close_on_free ? BIO_CLOSE : BIO_NOCLOSE);

    LUNAR_LEAVE(1);
}

/// @function new_socket
/// Creates a new socket BIO backed by a socket descriptor.
/// @tparam integer sock
/// @tparam[opt] boolean close_on_free
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_socket(lua_State* const L) {
    LUNAR_ENTER(1);

    const int sock = (int)lunar_checkwithin(L, 1, INT_MIN, INT_MAX);
    const int close_on_free = lua_toboolean(L, 2);

    BIO** const bio = lunar_class_create(BIO*, "lunarssl.bio");
    *bio = LUNAR_DCALL(*bio, BIO_new_socket, sock, close_on_free ? BIO_CLOSE : BIO_NOCLOSE);

    LUNAR_LEAVE(1);
}

/// @function new_pair
/// Creates a pair of BIOs where data written to one half is buffered and can be read by the other half.
/// @treturn lunarssl.bio
/// @treturn lunarssl.bio
LUNAR_FUNCTION int lunarssl_lua_bio_new_pair(lua_State* const L) {
    LUNAR_ENTER(0);

    size_t writebuf1 = lunar_optsize(L, 1, 0);
    size_t writebuf2 = lunar_optsize(L, 2, 0);

    BIO** const bio1 = lunar_class_create(BIO*, "lunarssl.bio");
    BIO** const bio2 = lunar_class_create(BIO*, "lunarssl.bio");

    LUNAR_TCALL(BIO_new_bio_pair, bio1, writebuf1, bio2, writebuf2);

    LUNAR_LEAVE(2);
}

LUNAR_INTERNAL const luaL_Reg lunarssl_bio_lib[] = {
    { "new_mem", lunarssl_lua_bio_new_mem },
    { "new_secmem", lunarssl_lua_bio_new_secmem },
    { "new_null", lunarssl_lua_bio_new_null },
    { "new_fd", lunarssl_lua_bio_new_fd },
    { "new_socket", lunarssl_lua_bio_new_socket },
    { "new_pair", lunarssl_lua_bio_new_pair },
    { NULL, NULL }
};

LUNAR_EXPORT int luaopen_lunarssl_bio(lua_State* const L) {
    LUNAR_ENTER(0);

    lunar_register_class("lunarssl.bio");
    lunar_register_library(lunarssl_bio_lib);

    LUNAR_LEAVE(1);
}
