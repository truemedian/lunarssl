/// @module lunarssl
#include "private.h"

#include "lunarssl.h"

#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stddef.h>

LUNAR_INTERNAL void lunarssl_init_openssl(lua_State* const L) {
    // TODO: synchronize
    static int initialized = 0;
    if (initialized) {
        return;
    }

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_OPENSSL, NULL) == 0) {
        luaL_error(L, "failed to initialize OpenSSL");
        return;
    }

    ERR_clear_error();
    initialized = 1;
}

/// @function version
/// Get compiled version information about the OpenSSL library.
/// @treturn table version information compiled into OpenSSL
LUNAR_EXPORT int lunarssl_lua_version(lua_State* const L) {
    LUNAR_ENTER(0);

    lua_createtable(L, 0, 3);

    lua_pushstring(L, OpenSSL_version(OPENSSL_VERSION_STRING));
    lua_setfield(L, -2, "short");

    lua_pushstring(L, OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
    lua_setfield(L, -2, "long");

    lua_pushstring(L, OpenSSL_version(OPENSSL_VERSION));
    lua_setfield(L, -2, "full");

    lua_pushstring(L, OpenSSL_version(OPENSSL_CFLAGS));
    lua_setfield(L, -2, "compiler");

    lua_pushstring(L, OpenSSL_version(OPENSSL_BUILT_ON));
    lua_setfield(L, -2, "built_on");

    lua_pushstring(L, OpenSSL_version(OPENSSL_PLATFORM));
    lua_setfield(L, -2, "platform");

    lua_pushstring(L, OpenSSL_version(OPENSSL_DIR));
    lua_setfield(L, -2, "openssldir");

    lua_pushstring(L, OpenSSL_version(OPENSSL_ENGINES_DIR));
    lua_setfield(L, -2, "enginesdir");

    lua_pushstring(L, OpenSSL_version(OPENSSL_MODULES_DIR));
    lua_setfield(L, -2, "modulesdir");

    lua_pushstring(L, OpenSSL_version(OPENSSL_CPU_INFO));
    lua_setfield(L, -2, "cpuinfo");

    lua_pushstring(L, OpenSSL_version(OPENSSL_WINCTX));
    lua_setfield(L, -2, "winctx");

    LUNAR_LEAVE(1);
}

/// @function info
/// Get runtime version information about the OpenSSL library.
/// @treturn table runtime information collected by OpenSSL
LUNAR_EXPORT int lunarssl_lua_info(lua_State* const L) {
    LUNAR_ENTER(0);

    lua_createtable(L, 0, 9);

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_CONFIG_DIR));
    lua_setfield(L, -2, "openssldir");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_ENGINES_DIR));
    lua_setfield(L, -2, "enginesdir");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_MODULES_DIR));
    lua_setfield(L, -2, "modulesdir");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_DSO_EXTENSION));
    lua_setfield(L, -2, "dso_extension");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR));
    lua_setfield(L, -2, "file_separator");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_LIST_SEPARATOR));
    lua_setfield(L, -2, "list_separator");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_SEED_SOURCE));
    lua_setfield(L, -2, "seed_source");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS));
    lua_setfield(L, -2, "cpuinfo");

    lua_pushstring(L, OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT));
    lua_setfield(L, -2, "winctx");

    LUNAR_LEAVE(1);
}

LUNAR_INTERNAL const luaL_Reg lunarssl_lib[] = {
    { "version", lunarssl_lua_version },
    { "info", lunarssl_lua_info },
    { NULL, NULL }
};

LUNAR_EXPORT int luaopen_lunarssl(lua_State* const L) {
    LUNAR_ENTER(0);

    lunarssl_init_openssl(L);
    lunar_register_library(lunarssl_lib);

    LUNAR_LEAVE(1);
}
