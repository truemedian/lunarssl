#pragma once

#include "lunarssl.h"
#include <openssl/bn.h>
#include <openssl/err.h>

#define lunarssl_bn_check(L, idx) *lunarssl_checkudata(L, BIGNUM*, idx, "lunarssl.bn")
BIGNUM* lunarssl_bn_check_loose(lua_State* L, int idx);
BIGNUM* lunarssl_bn_create(lua_State* L, int secure, lua_Integer value);

int luaopen_lunarssl_bn(lua_State* L);
