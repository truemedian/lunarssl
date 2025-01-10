#pragma once

#include "private.h"

#include <lua.h>
#include <openssl/bn.h>
#include <openssl/types.h>

#define BN_negate(bn) (BN_set_negative(bn, !BN_is_negative(bn)))

#define lunarssl_bn_check(L, idx) *lunar_class_check(BIGNUM*, idx, "lunarssl.bn.int")
LUNAR_EXPORT BIGNUM* lunarssl_bn_check_loose(lua_State* const L, const int idx);
LUNAR_EXPORT BIGNUM* lunarssl_bn_create(lua_State* const L, const lua_Integer value);

LUNAR_EXPORT int luaopen_lunarssl_bn(lua_State* const L);
