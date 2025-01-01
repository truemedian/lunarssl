/// @module lunarssl

#include <assert.h>
#include "lunarssl.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

static void lunarssl_init_openssl(lua_State* L) {
    // TODO: synchronize
    static int initialized = 0;
    if (initialized) {
        return;
    }

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_OPENSSL, NULL) == 0) {
        luaL_error(L, "failed to initialize OpenSSL");
        return;
    }

    initialized = 1;
}

#define XX(ENUM, OSSL_ENUM, NAME) NAME,
static const char* const lunarssl_version_list[] = {
    LUNARSSL_VERSION_MAP(XX)
};

static const char* const lunarssl_info_list[] = {
    LUNARSSL_INFO_MAP(XX)
};

#undef XX
#define XX(ENUM, OSSL_ENUM, NAME) \
    case ENUM:                    \
        type = OSSL_ENUM;         \
        break;

/// Get compiled version information about the OpenSSL library.
/// @function version
/// @tparam string kind Which kind of information to get.
/// @treturn string The requested information.
static int lunarssl_version(lua_State* L) {
    int kind = luaL_checkoption(L, 1, "long", lunarssl_version_list);

    int type = 0;
    switch (kind) {
        LUNARSSL_VERSION_MAP(XX)
    }

    lua_pushstring(L, OpenSSL_version(type));
    return 1;
}

/// Get runtime version information about the OpenSSL library.
/// @function info
/// @tparam string kind Which kind of information to get.
/// @treturn string The requested information.
static int lunarssl_info(lua_State* L) {
    int kind = luaL_checkoption(L, 1, NULL, lunarssl_info_list);

    int type = 0;
    switch (kind) {
        LUNARSSL_INFO_MAP(XX)
    }

    lua_pushstring(L, OPENSSL_info(type));
    return 1;
}

#undef XX

static void lunarssl_push_errortable(lua_State* L, unsigned long err) {
    lua_createtable(L, 0, 4);
    lua_pushstring(L, ERR_lib_error_string(err));
    lua_setfield(L, -2, "library");

    lua_pushstring(L, ERR_reason_error_string(err));
    lua_setfield(L, -2, "reason");

    char buf[256];
    ERR_error_string_n(err, buf, 256);
    lua_pushstring(L, buf);
    lua_setfield(L, -2, "message");

    lua_pushboolean(L, ERR_FATAL_ERROR(err));
    lua_setfield(L, -2, "fatal");
}

/// Get information about the most recent error and remove it from the error queue.
/// @tparam[opt] boolean peek When true, the error will not be removed from the queue.
/// @treturn table|nil The error state, or nil.
static int lunarssl_last_error(lua_State* L) {
    unsigned long err;
    if (lua_toboolean(L, 1)) {
        err = ERR_peek_error();
    } else {
        err = ERR_get_error();
    }

    if (err == 0) {
        lua_pushnil(L);
        return 1;
    }

    lunarssl_push_errortable(L, err);
    return 1;
}

/// Returns a list information on all errors in the error queue.
/// @treturn table A list of all errors in the error queue.
static int lunarssl_list_errors(lua_State* L) {

    lua_newtable(L);

    size_t len = 1;
    int err = ERR_get_error();
    while (err != 0) {
        lunarssl_push_errortable(L, err);
        lua_rawseti(L, -2, len++);
        err = ERR_get_error();
    }

    return 1;
}

/// Clear the error queue.
static int lunarssl_clear_error(lua_State* L) {
    (void)L;
    ERR_clear_error();
    return 0;
}

luaL_Reg lib_lunarssl[] = {
    { "version", lunarssl_version },
    { "info", lunarssl_info },
    { "last_error", lunarssl_last_error },
    { "list_errors", lunarssl_list_errors },
    { "clear_error", lunarssl_clear_error },
    { NULL, NULL }
};

int luaopen_lunarssl(lua_State* L) {
    lunarssl_init_openssl(L);

    luaL_newlib(L, lib_lunarssl);
    return 1;
}
