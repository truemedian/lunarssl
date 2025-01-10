/// @module lunarssl.bn
#include "private.h"

#include "bn.h"

#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stddef.h>

LUNAR_INTERNAL BN_ULONG lunarssl_bn_uabs(const lua_Integer value) {
    return value < 0 ? 0 - (BN_ULONG)value : (BN_ULONG)value;
}

LUNAR_EXPORT BIGNUM* lunarssl_bn_create(lua_State* const L, const lua_Integer value) {
    BIGNUM* const bn = LUNAR_DCALL0(bn != NULL, BN_new);

    if (value == 0)
        BN_zero(bn);
    else if (value == 1)
        BN_one(bn);
    else {
        LUNAR_TCALLF({ BN_free(bn); }, BN_set_word, bn, lunarssl_bn_uabs(value));
        BN_set_negative(bn, value < 0);
    }

    return bn;
}

LUNAR_EXPORT BIGNUM* lunarssl_bn_check_loose(lua_State* const L, const int idx) {
    if (lua_isinteger(L, idx)) {
        BIGNUM** const bn = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *bn = lunarssl_bn_create(L, lua_tointeger(L, idx));
        return *bn;
    }

    if (lua_isstring(L, idx)) {
        const char* const dec = lua_tostring(L, idx);
        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");

        *r = lunarssl_bn_create(L, 0);
        LUNAR_TCALLF({ BN_free(*r); }, BN_dec2bn, r, dec);
    }

    return lunarssl_bn_check(L, idx);
}

/// @function new
/// Creates a new BIGNUM.
/// @tparam[opt] integer value The initial value.
/// @treturn lunarssl.bn
LUNAR_FUNCTION int lunarssl_lua_bn_new(lua_State* const L) {
    LUNAR_ENTER(0);

    const lua_Integer value = luaL_optinteger(L, 1, 0);
    BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *r = lunarssl_bn_create(L, value);

    LUNAR_LEAVE(1);
}

/// @function from_hex
/// Creates a new BIGNUM from a hexadecimal string.
/// @tparam string hex
/// @treturn lunarssl.bn
LUNAR_FUNCTION int lunarssl_lua_bn_from_hex(lua_State* const L) {
    LUNAR_ENTER(1);

    const char* const hex = luaL_checkstring(L, 1);
    BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *r = lunarssl_bn_create(L, 0);

    LUNAR_TCALLF({ BN_free(*r); }, BN_hex2bn, r, hex);
    LUNAR_LEAVE(1);
}

/// @function from_dec
/// Creates a new BIGNUM from a decimal string.
/// @tparam string dec
/// @tparam[opt] boolean secure use a secure context.
/// @treturn lunarssl.bn
LUNAR_FUNCTION int lunarssl_lua_bn_from_dec(lua_State* const L) {
    LUNAR_ENTER(1);

    const char* const dec = luaL_checkstring(L, 1);
    BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *r = lunarssl_bn_create(L, 0);

    LUNAR_TCALLF({ BN_free(*r); }, BN_dec2bn, r, dec);
    LUNAR_LEAVE(1);
}

/// @function from_bin
/// Creates a new BIGNUM from a big-endian binary string.
/// @tparam string bin
/// @treturn lunarssl.bn
LUNAR_FUNCTION int lunarssl_lua_bn_from_bin(lua_State* const L) {
    LUNAR_ENTER(1);

    size_t len = 0;
    const char* const bin = luaL_checklstring(L, 1, &len);
    BIGNUM** const bn = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *bn = lunarssl_bn_create(L, 0);

    LUNAR_TCALL(BN_bin2bn, (const unsigned char*)bin, len, *bn);
    LUNAR_LEAVE(1);
}

/// @type lunarssl.bn.int

/// @function num_bytes
/// Returns the number of bytes needed to store the BIGNUM.
/// @tparam lunarssl.bn.int bn
/// @treturn integer
LUNAR_FUNCTION int lunarssl_lua_bn_int_num_bytes(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushinteger(L, BN_num_bytes(bn));
    LUNAR_LEAVE(1);
}

/// @function num_bits
/// Returns the number of significant bits needed in the BIGNUM.
///
/// Except for zero, this is `floor(log2(a)) + 1`.
/// @tparam lunarssl.bn.int bn
/// @treturn integer
LUNAR_FUNCTION int lunarssl_lua_bn_int_num_bits(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushinteger(L, BN_num_bits(bn));
    LUNAR_LEAVE(1);
}

/// @function cmp
/// Compares two BIGNUMs.
///
/// The following are equivalent for any comparison `~`: `a ~ b` and `a:cmp(b) ~ 0`.
/// @tparam lunarssl.bn.int a
/// @tparam lunarssl.bn.int b
/// @treturn integer -1 if `a < b`, 0 if `a == b`, 1 if `a > b`.
LUNAR_FUNCTION int lunarssl_lua_bn_int_cmp(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 2);

    lua_pushinteger(L, BN_cmp(a, b));
    LUNAR_LEAVE(1);
}

/// @function ucmp
/// Compares two BIGNUMs absolutely.
///
/// The following are equivalent for any comparison `~`: `|a| ~ |b|` and `a:ucmp(b) ~ 0`.
/// @tparam lunarssl.bn.int a
/// @tparam lunarssl.bn.int b
/// @treturn integer -1 if `|a| < |b|`, 0 if `|a| == |b|`, 1 if `|a| > |b|`.
LUNAR_FUNCTION int lunarssl_lua_bn_int_ucmp(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 2);

    lua_pushinteger(L, BN_ucmp(a, b));
    LUNAR_LEAVE(1);
}

/// @function is_zero
/// Returns true if the BIGNUM is zero.
/// @tparam lunarssl.bn.int bn
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_is_zero(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushboolean(L, BN_is_zero(bn));
    LUNAR_LEAVE(1);
}

/// @function is_negative
/// Returns true if the BIGNUM is negative.
/// @tparam lunarssl.bn.int bn
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_is_negative(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushboolean(L, BN_is_negative(bn));
    LUNAR_LEAVE(1);
}

/// @function is_one
/// Returns true if the BIGNUM is one.
/// @tparam lunarssl.bn.int bn
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_is_one(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushboolean(L, BN_is_one(bn));
    LUNAR_LEAVE(1);
}

/// @function is_odd
/// Returns true if the BIGNUM is odd.
/// @tparam lunarssl.bn.int bn
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_is_odd(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    lua_pushboolean(L, BN_is_odd(bn));
    LUNAR_LEAVE(1);
}

/// @function is_word
/// Returns true if the BIGNUM is equal to the given integer.
/// @tparam lunarssl.bn.int bn
/// @tparam integer word
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_is_word(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    lua_Integer const word = luaL_checkinteger(L, 2);

    if (BN_is_negative(bn) != word < 0)
        lua_pushboolean(L, 0);
    else
        lua_pushboolean(L, BN_abs_is_word(bn, lunarssl_bn_uabs(word)));

    LUNAR_LEAVE(1);
}

/// @function abs_is_word
/// Returns true if the absolute value of BIGNUM is equal to the absolute value of the given integer.
/// @tparam lunarssl.bn.int bn
/// @tparam integer word
/// @treturn boolean
LUNAR_FUNCTION int lunarssl_lua_bn_int_abs_is_word(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    lua_Integer const word = luaL_checkinteger(L, 2);

    lua_pushboolean(L, BN_abs_is_word(bn, lunarssl_bn_uabs(word)));
    LUNAR_LEAVE(1);
}

/// @function negate
/// Negates a BIGNUM. `bn = -bn`.
/// @tparam lunarssl.bn.int bn
LUNAR_FUNCTION int lunarssl_lua_bn_int_negate(lua_State* const L) {
    LUNAR_ENTER(1);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);

    BN_negate(bn);
    LUNAR_LEAVE(0);
}

/// @function add
/// Adds two BIGNUMs. `r = a + b`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a addend
/// @tparam lunarssl.bn.int b addend
LUNAR_FUNCTION int lunarssl_lua_bn_int_add(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);

    LUNAR_TCALL(BN_add, r, a, b);
    LUNAR_LEAVE(0);
}

/// @function sub
/// Subtracts two BIGNUMs. `r = a - b`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a subtrahend
/// @tparam lunarssl.bn.int b minuend
LUNAR_FUNCTION int lunarssl_lua_bn_int_sub(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);

    LUNAR_TCALL(BN_sub, r, a, b);
    LUNAR_LEAVE(0);
}

/// @function mul
/// Multiplies two BIGNUMs. `r = a * b`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a multiplicand
/// @tparam lunarssl.bn.int b multiplier
LUNAR_FUNCTION int lunarssl_lua_bn_int_mul(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mul, r, a, b, ctx);
    LUNAR_LEAVE(0);
}

/// @function sqr
/// Squares a BIGNUM. `r = a^2`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a base
LUNAR_FUNCTION int lunarssl_lua_bn_int_sqr(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_sqr, r, a, ctx);
    LUNAR_LEAVE(0);
}

/// @function div
/// Divides two BIGNUMs. `r = a / b` and `rem = a % b`.
/// @tparam lunarssl.bn.int|nil q quotient result location
/// @tparam lunarssl.bn.int|nil r remainder result location
/// @tparam lunarssl.bn.int a dividend
/// @tparam lunarssl.bn.int b divisor
LUNAR_FUNCTION int lunarssl_lua_bn_int_div(lua_State* const L) {
    LUNAR_ENTER(4);

    BIGNUM* const q = lua_isnoneornil(L, 1) ? NULL : lunarssl_bn_check(L, 1);
    BIGNUM* const r = lua_isnoneornil(L, 2) ? NULL : lunarssl_bn_check(L, 2);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 4);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_div, q, r, a, b, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod
/// Calculates the remainder of a division. `rem = a % m`.
/// @tparam lunarssl.bn.int r remainder result location.
/// @tparam lunarssl.bn.int a dividend
/// @tparam lunarssl.bn.int m divisor
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod, r, a, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function nnmod
/// Reduces a modulo m and returns the non-negative remainder.
/// @tparam lunarssl.bn.int r remainder result location.
/// @tparam lunarssl.bn.int a dividend
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_nnmod(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const rem = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_nnmod, rem, a, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function exp
/// Raises a BIGNUM to a power. `r = a^p`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a base
/// @tparam lunarssl.bn.int p exponent
LUNAR_FUNCTION int lunarssl_lua_bn_int_exp(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const p = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_exp, r, a, p, ctx);
    LUNAR_LEAVE(0);
}

/// @function gcd
/// Calculates the greatest common divisor of two BIGNUMs. `r = gcd(a, b)`. `r` may alias `a` or `b`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a
/// @tparam lunarssl.bn.int b
LUNAR_FUNCTION int lunarssl_lua_bn_int_gcd(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_gcd, r, a, b, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_add
/// Adds two BIGNUMs modulo m. `r = (a + b) mod m`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a addend
/// @tparam lunarssl.bn.int b addend
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_add(lua_State* const L) {
    LUNAR_ENTER(4);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_add, r, a, b, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_sub
/// Subtracts two BIGNUMs modulo m. `r = (a - b) mod m`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a subtrahend
/// @tparam lunarssl.bn.int b minuend
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_sub(lua_State* const L) {
    LUNAR_ENTER(4);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_sub, r, a, b, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_mul
/// Multiplies two BIGNUMs modulo m. `r = (a * b) mod m`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a multiplicand
/// @tparam lunarssl.bn.int b multiplier
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_mul(lua_State* const L) {
    LUNAR_ENTER(4);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_mul, r, a, b, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_sqr
/// Squares a BIGNUM modulo m. `r = (a^2) mod m`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a base
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_sqr(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_sqr, r, a, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_sqrt
/// Calculates the modular square root of a BIGNUM. `r^2 = a mod p`. `p` must be prime.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a radicand
/// @tparam lunarssl.bn.int p modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_sqrt(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const p = lunarssl_bn_check_loose(L, 3);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_sqrt, r, a, p, ctx);
    LUNAR_LEAVE(0);
}

/// @function mod_exp
/// Raises a BIGNUM to a power modulo m. `r = a^p mod m`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a base
/// @tparam lunarssl.bn.int p exponent
/// @tparam lunarssl.bn.int m modulus
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_exp(lua_State* const L) {
    LUNAR_ENTER(4);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* const p = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* const m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    LUNAR_FCALL({ BN_CTX_free(ctx); }, BN_mod_exp, r, a, p, m, ctx);
    LUNAR_LEAVE(0);
}

/// @function add_word
/// Adds an integer to a BIGNUM. `r += a`.
/// @tparam lunarssl.bn.int r result location
/// @tparam integer a addend
LUNAR_FUNCTION int lunarssl_lua_bn_int_add_word(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0)
        LUNAR_TCALL(BN_sub_word, r, lunarssl_bn_uabs(word));
    else
        LUNAR_TCALL(BN_add_word, r, lunarssl_bn_uabs(word));
    LUNAR_LEAVE(0);
}

/// @function sub_word
/// Subtracts an integer from a BIGNUM. `r -= a`.
/// @tparam lunarssl.bn.int r result location
/// @tparam integer a minuend
LUNAR_FUNCTION int lunarssl_lua_bn_int_sub_word(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0)
        LUNAR_TCALL(BN_add_word, r, lunarssl_bn_uabs(word));
    else
        LUNAR_TCALL(BN_sub_word, r, lunarssl_bn_uabs(word));
    LUNAR_LEAVE(0);
}

/// @function mul_word
/// Multiplies a BIGNUM by an integer. `r *= a`.
/// @tparam lunarssl.bn.int r result location
/// @tparam integer a multiplier
LUNAR_FUNCTION int lunarssl_lua_bn_int_mul_word(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0) {
        LUNAR_TCALL(BN_mul_word, r, lunarssl_bn_uabs(word));
        BN_negate(r);
    } else
        LUNAR_TCALL(BN_mul_word, r, lunarssl_bn_uabs(word));
    LUNAR_LEAVE(0);
}

/// @function div_word
/// Divides a BIGNUM by an integer and returns the remainder. `r /= a`.
/// @tparam lunarssl.bn.int r result location
/// @tparam integer a divisor
/// @treturn integer remainder
LUNAR_FUNCTION int lunarssl_lua_bn_int_div_word(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const lua_Integer word = luaL_checkinteger(L, 2);

    BN_ULONG rem = 0;
    if (word < 0) {
        rem = LUNAR_DCALL(rem != (BN_ULONG)-1, BN_div_word, r, lunarssl_bn_uabs(word));
        BN_negate(r);
    } else {
        rem = LUNAR_DCALL(rem != (BN_ULONG)-1, BN_div_word, r, lunarssl_bn_uabs(word));
    }

    lua_pushinteger(L, (lua_Integer)rem);
    LUNAR_LEAVE(1);
}

/// @function mod_word
/// Calculates the remainder of a division by an unsigned word. `a % m`.
/// @tparam lunarssl.bn.int a dividend
/// @tparam integer m divisor
/// @treturn integer remainder
LUNAR_FUNCTION int lunarssl_lua_bn_int_mod_word(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const lua_Integer word = luaL_checkinteger(L, 2);

    BN_ULONG rem = 0;
    if (word < 0) {
        rem = LUNAR_DCALL(rem != (BN_ULONG)-1, BN_mod_word, bn, lunarssl_bn_uabs(word));
    } else {
        rem = LUNAR_DCALL(rem != (BN_ULONG)-1, BN_mod_word, bn, lunarssl_bn_uabs(word));
    }

    lua_pushinteger(L, (lua_Integer)rem);
    LUNAR_LEAVE(1);
}

/// @function to_hex
/// Converts a BIGNUM to a hexadecimal string.
/// @tparam lunarssl.bn.int bn
/// @treturn string
LUNAR_FUNCTION int lunarssl_lua_bn_int_to_hex(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    char* const hex = LUNAR_DCALL(hex != NULL, BN_bn2hex, bn);
    lua_pushstring(L, hex);

    OPENSSL_free(hex);
    LUNAR_LEAVE(1);
}

/// @function to_dec
/// Converts a BIGNUM to a decimal string.
/// @tparam lunarssl.bn.int bn
/// @treturn string
LUNAR_FUNCTION int lunarssl_lua_bn_int_to_dec(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);

    char* const dec = LUNAR_DCALL(dec != NULL, BN_bn2dec, bn);
    lua_pushstring(L, dec);

    OPENSSL_free(dec);
    LUNAR_LEAVE(1);
}

/// @function to_bin
/// Converts a BIGNUM to a big-endian binary string.
/// @tparam lunarssl.bn.int bn
/// @treturn string
LUNAR_FUNCTION int lunarssl_lua_bn_int_to_bin(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const int len = BN_num_bytes(bn);

    unsigned char* const bin = (unsigned char*)OPENSSL_malloc(len);
    const int written = LUNAR_DCALLF(written != -1, { OPENSSL_free(bin); }, BN_bn2binpad, bn, bin, len);

    lua_pushlstring(L, (const char*)bin, written);
    OPENSSL_free(bin);
    LUNAR_LEAVE(1);
}

/// @function set_bit
/// Sets a bit in a BIGNUM. `a |= (1 << n)`
/// @tparam lunarssl.bn.int bn
/// @tparam integer bit index of the bit to set, starting at 0.
LUNAR_FUNCTION int lunarssl_lua_bn_int_set_bit(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const lua_Integer bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    LUNAR_TCALL(BN_set_bit, bn, (int)bit);
    LUNAR_LEAVE(0);
}

/// @function clear_bit
/// Clears a bit in a BIGNUM. `a &= ~(1 << n)`
/// @tparam lunarssl.bn.int bn
/// @tparam integer bit index of the bit to clear, starting at 0.
LUNAR_FUNCTION int lunarssl_lua_bn_int_clear_bit(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const lua_Integer bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    LUNAR_TCALL(BN_clear_bit, bn, (int)bit);
    LUNAR_LEAVE(0);
}

/// @function test_bit
/// Tests a bit in a BIGNUM.
/// @tparam lunarssl.bn.int bn
/// @tparam integer bit index of the bit to test, starting at 0.
/// @treturn boolean If the bit is set.
LUNAR_FUNCTION int lunarssl_lua_bn_int_test_bit(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const lua_Integer bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    lua_pushboolean(L, BN_is_bit_set(bn, (int)bit));
    LUNAR_LEAVE(1);
}

/// @function mask_bits
/// Truncates a BIGNUM to a certain number of bits. `a &= ~((~0) << n))`.
///
/// Returns an error if the number is already small enough.
/// @tparam lunarssl.bn.int bn
/// @tparam integer bits number of low bits to keep.
LUNAR_FUNCTION int lunarssl_lua_bn_int_mask_bits(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);
    const lua_Integer bits = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bits >= 0, 2, "bits must be non-negative");

    LUNAR_TCALL(BN_mask_bits, bn, (int)bits);
    LUNAR_LEAVE(0);
}

/// @function lshift
/// Shifts a BIGNUM left by a certain number of bits. `r = a << shamt`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a value
/// @tparam integer shamt number of bits to shift by
LUNAR_FUNCTION int lunarssl_lua_bn_int_lshift(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const lua_Integer shamt = luaL_checkinteger(L, 3);
    luaL_argcheck(L, shamt >= 0, 2, "shamt must be non-negative");

    LUNAR_TCALL(BN_lshift, r, a, (int)shamt);
    LUNAR_LEAVE(0);
}

/// @function rshift
/// Shifts a BIGNUM right by a certain number of bits. `r = a >> shamt`.
/// @tparam lunarssl.bn.int r result location
/// @tparam lunarssl.bn.int a value
/// @tparam integer shamt number of bits to shift by
LUNAR_FUNCTION int lunarssl_lua_bn_int_rshift(lua_State* const L) {
    LUNAR_ENTER(3);

    BIGNUM* const r = lunarssl_bn_check(L, 1);
    const BIGNUM* const a = lunarssl_bn_check_loose(L, 2);
    const lua_Integer shamt = luaL_checkinteger(L, 3);
    luaL_argcheck(L, shamt >= 0, 2, "shamt must be non-negative");

    LUNAR_TCALL(BN_rshift, r, a, (int)shamt);
    LUNAR_LEAVE(0);
}

/// @function clear
/// Clears the BIGNUM and sets it to zero.
/// @tparam lunarssl.bn.int bn
LUNAR_FUNCTION int lunarssl_lua_bn_int_clear(lua_State* const L) {
    LUNAR_ENTER(1);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);
    BN_clear(bn);
    LUNAR_LEAVE(0);
}

/// @function swap
/// Swaps two BIGNUMs.
/// @tparam lunarssl.bn.int a
/// @tparam lunarssl.bn.int b
LUNAR_FUNCTION int lunarssl_lua_bn_int_swap(lua_State* const L) {
    LUNAR_ENTER(2);

    BIGNUM* const a = lunarssl_bn_check(L, 1);
    BIGNUM* const b = lunarssl_bn_check(L, 2);
    BN_swap(a, b);
    LUNAR_LEAVE(0);
}

/// @function copy
/// Copies a BIGNUM.
/// @tparam lunarssl.bn.int from
/// @tparam lunarssl.bn.int to
LUNAR_FUNCTION int lunarssl_lua_bn_int_copy(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const from = lunarssl_bn_check(L, 1);
    BIGNUM* const to = lunarssl_bn_check(L, 2);

    LUNAR_TCALL(BN_copy, to, from);
    LUNAR_LEAVE(0);
}

/// @function dup
/// Duplicates a BIGNUM.
/// @tparam lunarssl.bn.int bn
/// @treturn lunarssl.bn
LUNAR_FUNCTION int lunarssl_lua_bn_int_dup(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    BIGNUM** const dup = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *dup = LUNAR_DCALL(dup != NULL, BN_dup, bn);
    LUNAR_LEAVE(1);
}

/// @function to_word
/// Converts a BIGNUM to an unsigned word or returns nil if it is too large.
/// @tparam lunarssl.bn.int bn
/// @treturn integer|nil
LUNAR_FUNCTION int lunarssl_lua_bn_int_to_word(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    BN_ULONG word = BN_get_word(bn);
    if (word == (BN_ULONG)-1) {
        lua_pushnil(L);
        LUNAR_LEAVE(1);
    }

    // FIXME: convert to integer first
    if (BN_is_negative(bn))
        word = -word;

    lua_pushinteger(L, (lua_Integer)word);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___tostring(lua_State* const L) {
    LUNAR_ENTER(1);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    char* const hex = LUNAR_DCALL(hex != NULL, BN_bn2hex, bn);

    lua_pushfstring(L, "lunarssl.bn.int: %sh", hex);
    OPENSSL_free(hex);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___add(lua_State* const L) {
    LUNAR_ENTER(2);

    if (lua_isinteger(L, 1)) {
        const lua_Integer a = luaL_checkinteger(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, b);

        if (a < 0) // (-a) + b = b - a or b + (-a) = b - a
            LUNAR_TCALLF({ BN_free(*r); }, BN_sub_word, *r, lunarssl_bn_uabs(a));
        else // a + b = b + a or b + a = b + a
            LUNAR_TCALLF({ BN_free(*r); }, BN_add_word, *r, lunarssl_bn_uabs(a));

    } else if (lua_isinteger(L, 2)) {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const lua_Integer b = luaL_checkinteger(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, a);

        if (b < 0) // (-a) + b = b - a or b + (-a) = b - a
            LUNAR_TCALLF({ BN_free(*r); }, BN_sub_word, *r, lunarssl_bn_uabs(b));
        else // a + b = b + a or b + a = b + a
            LUNAR_TCALLF({ BN_free(*r); }, BN_add_word, *r, lunarssl_bn_uabs(b));
    } else {
        const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
        const BIGNUM* const b = lunarssl_bn_check_loose(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        LUNAR_TCALLF({ BN_free(*r); }, BN_add, *r, a, b);
    }

    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___sub(lua_State* const L) {
    LUNAR_ENTER(2);

    if (lua_isinteger(L, 1)) {
        const lua_Integer a = luaL_checkinteger(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, b);
        BN_negate(*r);

        if (a < 0) // (-w) - b = -b - w
            LUNAR_TCALLF({ BN_free(*r); }, BN_sub_word, *r, lunarssl_bn_uabs(a));
        else // w - b = -b + w
            LUNAR_TCALLF({ BN_free(*r); }, BN_add_word, *r, lunarssl_bn_uabs(a));
    } else if (lua_isinteger(L, 2)) {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const lua_Integer b = luaL_checkinteger(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, a);

        if (b < 0) // b - (-w) = b + w
            LUNAR_TCALLF({ BN_free(*r); }, BN_add_word, *r, lunarssl_bn_uabs(b));
        else // b - w = b - w
            LUNAR_TCALLF({ BN_free(*r); }, BN_sub_word, *r, lunarssl_bn_uabs(b));
    } else {
        const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
        const BIGNUM* const b = lunarssl_bn_check_loose(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        LUNAR_TCALLF({ BN_free(*r); }, BN_sub, *r, a, b);
    }

    luaL_setmetatable(L, "lunarssl.bn.int");
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___mul(lua_State* const L) {
    LUNAR_ENTER(2);

    if (lua_isinteger(L, 1)) {
        const lua_Integer a = luaL_checkinteger(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, b);

        if (a < 0) {
            LUNAR_TCALLF({ BN_free(*r); }, BN_mul_word, *r, lunarssl_bn_uabs(a));
            BN_negate(*r);
        } else
            LUNAR_TCALLF({ BN_free(*r); }, BN_mul_word, *r, lunarssl_bn_uabs(a));
    } else if (lua_isinteger(L, 2)) {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const lua_Integer b = luaL_checkinteger(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, a);

        if (b < 0) {
            LUNAR_TCALLF({ BN_free(*r); }, BN_mul_word, *r, lunarssl_bn_uabs(b));
            BN_negate(*r);
        } else
            LUNAR_TCALLF({ BN_free(*r); }, BN_mul_word, *r, lunarssl_bn_uabs(b));
    } else {
        const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
        const BIGNUM* const b = lunarssl_bn_check_loose(L, 2);
        BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_mul, *r, a, b, ctx);
    }

    luaL_setmetatable(L, "lunarssl.bn.int");
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___div(lua_State* const L) {
    LUNAR_ENTER(2);

    if (lua_isinteger(L, 1)) {
        const lua_Integer a = luaL_checkinteger(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);
        BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, a);

        LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_div, *r, NULL, *r, b, ctx);
    } else if (lua_isinteger(L, 2)) {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const lua_Integer b = luaL_checkinteger(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = LUNAR_DCALL(*r != NULL, BN_dup, a);

        if (b < 0) {
            LUNAR_TCALLF({ BN_free(*r); }, BN_div_word, *r, (BN_ULONG)-b);
            BN_negate(*r);
        } else
            LUNAR_TCALLF({ BN_free(*r); }, BN_div_word, *r, (BN_ULONG)b);
    } else {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);
        BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_div, *r, NULL, a, b, ctx);
    }

    luaL_setmetatable(L, "lunarssl.bn.int");
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___mod(lua_State* const L) {
    LUNAR_ENTER(2);

    if (lua_isinteger(L, 1)) {
        const lua_Integer a = luaL_checkinteger(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);
        BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, a);

        int const a_neg = a < 0;
        int const b_neg = BN_is_negative(b);

        LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_div, NULL, *r, *r, b, ctx);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r))
            LUNAR_TCALLF({ BN_free(*r); }, BN_add, *r, *r, b);

    } else if (lua_isinteger(L, 2)) {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const lua_Integer b = luaL_checkinteger(L, 2);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        int const a_neg = BN_is_negative(a);
        int const b_neg = b < 0;

        BN_ULONG rem = LUNAR_DCALLF(rem != (BN_ULONG)-1, { BN_free(*r); }, BN_mod_word, a, lunarssl_bn_uabs(b));
        LUNAR_TCALLF({ BN_free(*r); }, BN_set_word, *r, rem);
        if (a_neg)
            BN_negate(*r);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r)) {
            BIGNUM* const bn = lunarssl_bn_create(L, b);
            LUNAR_FCALLF({ BN_free(bn); }, { BN_free(*r); }, BN_add, *r, *r, bn);
        }
    } else {
        const BIGNUM* const a = lunarssl_bn_check(L, 1);
        const BIGNUM* const b = lunarssl_bn_check(L, 2);
        BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

        BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
        *r = lunarssl_bn_create(L, 0);

        int const a_neg = BN_is_negative(a);
        int const b_neg = BN_is_negative(b);

        LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_mod, *r, a, b, ctx);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r))
            LUNAR_TCALLF({ BN_free(*r); }, BN_add, *r, *r, b);
    }

    luaL_setmetatable(L, "lunarssl.bn.int");
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___pow(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check_loose(L, 1);
    const BIGNUM* const p = lunarssl_bn_check_loose(L, 2);
    BN_CTX* const ctx = LUNAR_DCALL0(ctx != NULL, BN_CTX_new);

    BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *r = BN_new();

    LUNAR_FCALLF({ BN_CTX_free(ctx); }, { BN_free(*r); }, BN_exp, *r, a, p, ctx);

    luaL_setmetatable(L, "lunarssl.bn.int");
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___unm(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const bn = lunarssl_bn_check(L, 1);
    BIGNUM** const r = lunar_class_create(BIGNUM*, "lunarssl.bn.int");
    *r = LUNAR_DCALL(*r != NULL, BN_dup, bn);
    BN_negate(*r);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___eq(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check(L, 1);
    const BIGNUM* const b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) == 0);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___lt(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check(L, 1);
    const BIGNUM* const b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) < 0);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___le(lua_State* const L) {
    LUNAR_ENTER(2);

    const BIGNUM* const a = lunarssl_bn_check(L, 1);
    const BIGNUM* const b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) <= 0);
    LUNAR_LEAVE(1);
}

LUNAR_FUNCTION int lunarssl_lua_bn_int___gc(lua_State* const L) {
    LUNAR_ENTER(1);

    BIGNUM* const bn = lunarssl_bn_check(L, 1);
    BN_free(bn);
    LUNAR_LEAVE(0);
}

LUNAR_INTERNAL const luaL_Reg lunarssl_lib_bn[] = {
    { "new", lunarssl_lua_bn_new },
    { "from_hex", lunarssl_lua_bn_from_hex },
    { "from_dec", lunarssl_lua_bn_from_dec },
    { "from_bin", lunarssl_lua_bn_from_bin },
    { NULL, NULL }
};

LUNAR_INTERNAL const luaL_Reg lunarssl_lib_bn_int[] = {
    // information and comparison
    { "num_bytes", lunarssl_lua_bn_int_num_bytes },
    { "num_bits", lunarssl_lua_bn_int_num_bits },
    { "cmp", lunarssl_lua_bn_int_cmp },
    { "ucmp", lunarssl_lua_bn_int_ucmp },
    { "is_zero", lunarssl_lua_bn_int_is_zero },
    { "is_one", lunarssl_lua_bn_int_is_one },
    { "is_odd", lunarssl_lua_bn_int_is_odd },
    { "is_word", lunarssl_lua_bn_int_is_word },
    { "is_negative", lunarssl_lua_bn_int_is_negative },
    { "abs_is_word", lunarssl_lua_bn_int_abs_is_word },

    // normal arithmetic
    { "negate", lunarssl_lua_bn_int_negate },
    { "add", lunarssl_lua_bn_int_add },
    { "sub", lunarssl_lua_bn_int_sub },
    { "mul", lunarssl_lua_bn_int_mul },
    { "sqr", lunarssl_lua_bn_int_sqr },
    { "div", lunarssl_lua_bn_int_div },
    { "mod", lunarssl_lua_bn_int_mod },
    { "nnmod", lunarssl_lua_bn_int_nnmod },
    { "exp", lunarssl_lua_bn_int_exp },
    { "gcd", lunarssl_lua_bn_int_gcd },

    // modular arithmetic
    { "mod_add", lunarssl_lua_bn_int_mod_add },
    { "mod_sub", lunarssl_lua_bn_int_mod_sub },
    { "mod_mul", lunarssl_lua_bn_int_mod_mul },
    { "mod_sqr", lunarssl_lua_bn_int_mod_sqr },
    { "mod_sqrt", lunarssl_lua_bn_int_mod_sqrt },
    { "mod_exp", lunarssl_lua_bn_int_mod_exp },

    // arithmetic with scalar
    { "add_word", lunarssl_lua_bn_int_add_word },
    { "sub_word", lunarssl_lua_bn_int_sub_word },
    { "mul_word", lunarssl_lua_bn_int_mul_word },
    { "div_word", lunarssl_lua_bn_int_div_word },
    { "mod_word", lunarssl_lua_bn_int_mod_word },

    // from bignum
    { "to_hex", lunarssl_lua_bn_int_to_hex },
    { "to_dec", lunarssl_lua_bn_int_to_dec },
    { "to_bin", lunarssl_lua_bn_int_to_bin },
    { "to_word", lunarssl_lua_bn_int_to_word },

    // bit manipulation
    { "set_bit", lunarssl_lua_bn_int_set_bit },
    { "clear_bit", lunarssl_lua_bn_int_clear_bit },
    { "test_bit", lunarssl_lua_bn_int_test_bit },
    { "mask_bits", lunarssl_lua_bn_int_mask_bits },
    { "lshift", lunarssl_lua_bn_int_lshift },
    { "rshift", lunarssl_lua_bn_int_rshift },

    // other
    { "clear", lunarssl_lua_bn_int_clear },
    { "swap", lunarssl_lua_bn_int_swap },
    { "copy", lunarssl_lua_bn_int_copy },
    { "dup", lunarssl_lua_bn_int_dup },
    { NULL, NULL }
};

LUNAR_INTERNAL const luaL_Reg lunarssl_lib_bn_int_mt[] = {
    { "__tostring", lunarssl_lua_bn_int___tostring },
    { "__add", lunarssl_lua_bn_int___add },
    { "__sub", lunarssl_lua_bn_int___sub },
    { "__mul", lunarssl_lua_bn_int___mul },
    { "__div", lunarssl_lua_bn_int___div },
    { "__idiv", lunarssl_lua_bn_int___div },
    { "__mod", lunarssl_lua_bn_int___mod },
    { "__pow", lunarssl_lua_bn_int___pow },
    { "__unm", lunarssl_lua_bn_int___unm },
    { "__eq", lunarssl_lua_bn_int___eq },
    { "__lt", lunarssl_lua_bn_int___lt },
    { "__le", lunarssl_lua_bn_int___le },
    { "__gc", lunarssl_lua_bn_int___gc },
    { NULL, NULL }
};

LUNAR_EXPORT int luaopen_lunarssl_bn(lua_State* const L) {
    LUNAR_ENTER(0);

    lunar_register_class("lunarssl.bn.int");
    lunar_register_append(lunarssl_lib_bn_int);
    lunar_register_append(lunarssl_lib_bn_int_mt);
    lua_pop(L, 1);

    lunar_register_library(lunarssl_lib_bn);
    lunar_register_append(lunarssl_lib_bn_int);
    LUNAR_LEAVE(1);
}
