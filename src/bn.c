/// @module lunarssl.bn

#include "bn.h"

#define LSSL_ERR_REASON (ERR_reason_error_string(ERR_get_error()))

#define LSSL_BN_CALL(FN, ...)                              \
    if (!(FN(__VA_ARGS__))) {                              \
        luaL_error(L, #FN " failed: %s", LSSL_ERR_REASON); \
        unreachable();                                     \
    }

#define LSSL_BNCTX_CALL(FN, CTX, ...)                      \
    if (!(FN(__VA_ARGS__, CTX))) {                         \
        BN_CTX_free(CTX);                                  \
        luaL_error(L, #FN " failed: %s", LSSL_ERR_REASON); \
        unreachable();                                     \
    }                                                      \
    BN_CTX_free(CTX);

#define LSSL_BNR_CALL(FN, R, ...)                          \
    if (!(FN(R, __VA_ARGS__))) {                           \
        BN_free(R);                                        \
        luaL_error(L, #FN " failed: %s", LSSL_ERR_REASON); \
        unreachable();                                     \
    }

#define LSSL_BNRCTX_CALL(FN, R, CTX, ...)                  \
    if (!(FN(R, __VA_ARGS__, CTX))) {                      \
        BN_free(R);                                        \
        BN_CTX_free(CTX);                                  \
        luaL_error(L, #FN " failed: %s", LSSL_ERR_REASON); \
        unreachable();                                     \
    }                                                      \
    BN_CTX_free(CTX);

#define LSSL_MIN_ULONG ((BN_ULONG)1 << ((BN_BYTES * 8) - 1))

#define LSSL_BN_negate(bn) BN_set_negative(bn, !BN_is_negative(bn))

static BN_CTX* lunarssl_bn_ctx(lua_State* L, int secure_idx) {
    int secure = secure_idx == -1 ? 0 : lua_toboolean(L, secure_idx);
    BN_CTX* ctx;

    if (secure) {
        ctx = BN_CTX_secure_new();
    } else {
        ctx = BN_CTX_new();
    }

    if (!ctx)
        luaL_error(L, "BN_CTX_new failed: %s", LSSL_ERR_REASON);

    return ctx;
}

BIGNUM* lunarssl_bn_create(lua_State* L, int secure, lua_Integer value) {
    BIGNUM* r;
    if (secure) {
        r = BN_secure_new();
    } else {
        r = BN_new();
    }

    if (!r)
        luaL_error(L, "BN_new failed: %s", LSSL_ERR_REASON);

    if (value == 0) {
        BN_zero(r);
    } else if (value == 1) {
        BN_one(r);
    } else if (value < 0 && ((BN_ULONG)value) != LSSL_MIN_ULONG) {
        LSSL_BNR_CALL(BN_set_word, r, (BN_ULONG)-value);
        BN_set_negative(r, 1);
    } else {
        LSSL_BNR_CALL(BN_set_word, r, (BN_ULONG)value);
    }

    return r;
}

BIGNUM* lunarssl_bn_check_loose(lua_State* L, int idx) {
    if (lua_isinteger(L, idx)) {
        BIGNUM** r = lunarssl_newudata(L, BIGNUM*, 0);
        *r = lunarssl_bn_create(L, 0, lua_tointeger(L, idx));
        return *r;
    }

    return lunarssl_bn_check(L, idx);
}

/// @function new
/// Creates a new BIGNUM.
/// @tparam[opt] integer value The initial value.
/// @tparam[opt] boolean secure use a secure context.
/// @treturn lunarssl.bn
static int lunarssl_bn_new(lua_State* L) {
    lua_Integer value = luaL_optinteger(L, 1, 0);
    int secure = lua_toboolean(L, 2);

    BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *r = lunarssl_bn_create(L, secure, value);
    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

/// @function from_hex
/// Creates a new BIGNUM from a hexadecimal string.
/// @tparam string hex
/// @tparam[opt] boolean secure use a secure context.
/// @treturn lunarssl.bn
static int lunarssl_bn_from_hex(lua_State* L) {
    int secure = lua_toboolean(L, 2);

    BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *r = lunarssl_bn_create(L, secure, 0);

    const char* hex = luaL_checkstring(L, 1);
    if (!BN_hex2bn(r, hex)) {
        BN_free(*r);
        return luaL_error(L, "BN_hex2bn failed: %s", LSSL_ERR_REASON);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

/// @function from_dec
/// Creates a new BIGNUM from a decimal string.
/// @tparam string dec
/// @tparam[opt] boolean secure use a secure context.
/// @treturn lunarssl.bn
static int lunarssl_bn_from_dec(lua_State* L) {
    int secure = lua_toboolean(L, 2);

    BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *r = lunarssl_bn_create(L, secure, 0);

    const char* dec = luaL_checkstring(L, 1);
    if (!BN_dec2bn(r, dec)) {
        BN_free(*r);
        return luaL_error(L, "BN_dec2bn failed: %s", LSSL_ERR_REASON);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

/// @function from_bin
/// Creates a new BIGNUM from a big-endian binary string.
/// @tparam string bin
/// @tparam[opt] boolean secure use a secure context.
/// @treturn lunarssl.bn
static int lunarssl_bn_from_bin(lua_State* L) {
    int secure = lua_toboolean(L, 2);

    BIGNUM** bn = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *bn = lunarssl_bn_create(L, secure, 0);

    size_t len;
    const char* bin = luaL_checklstring(L, 1, &len);
    LSSL_BN_CALL(BN_bin2bn, (const unsigned char*)bin, len, *bn);

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

/// @type lunarssl.bn

/// @function num_bytes
/// Returns the number of bytes needed to store the BIGNUM.
/// @tparam lunarssl.bn bn
/// @treturn integer
static int lunarssl_bn_num_bytes(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushinteger(L, BN_num_bytes(bn));
    return 1;
}

/// @function num_bits
/// Returns the number of significant bits needed in the BIGNUM.
///
/// Except for zero, this is `floor(log2(a)) + 1`.
/// @tparam lunarssl.bn bn
/// @treturn integer
static int lunarssl_bn_num_bits(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushinteger(L, BN_num_bits(bn));
    return 1;
}

/// @function cmp
/// Compares two BIGNUMs.
///
/// The following are equivalent for any comparison `~`: `a ~ b` and `a:cmp(b) ~ 0`.
/// @tparam lunarssl.bn a
/// @tparam lunarssl.bn b
/// @treturn integer -1 if `a < b`, 0 if `a == b`, 1 if `a > b`.
static int lunarssl_bn_cmp(lua_State* L) {
    const BIGNUM* a = lunarssl_bn_check_loose(L, 1);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 2);

    lua_pushinteger(L, BN_cmp(a, b));
    return 1;
}

/// @function ucmp
/// Compares two BIGNUMs absolutely.
///
/// The following are equivalent for any comparison `~`: `|a| ~ |b|` and `a:ucmp(b) ~ 0`.
/// @tparam lunarssl.bn a
/// @tparam lunarssl.bn b
/// @treturn integer -1 if `|a| < |b|`, 0 if `|a| == |b|`, 1 if `|a| > |b|`.
static int lunarssl_bn_ucmp(lua_State* L) {
    const BIGNUM* a = lunarssl_bn_check_loose(L, 1);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 2);

    lua_pushinteger(L, BN_ucmp(a, b));
    return 1;
}

/// @function is_zero
/// Returns true if the BIGNUM is zero.
/// @tparam lunarssl.bn bn
/// @treturn boolean
static int lunarssl_bn_is_zero(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushboolean(L, BN_is_zero(bn));
    return 1;
}

/// @function is_negative
/// Returns true if the BIGNUM is negative.
/// @tparam lunarssl.bn bn
/// @treturn boolean
static int lunarssl_bn_is_negative(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushboolean(L, BN_is_negative(bn));
    return 1;
}

/// @function is_one
/// Returns true if the BIGNUM is one.
/// @tparam lunarssl.bn bn
/// @treturn boolean
static int lunarssl_bn_is_one(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushboolean(L, BN_is_one(bn));
    return 1;
}

/// @function is_odd
/// Returns true if the BIGNUM is odd.
/// @tparam lunarssl.bn bn
/// @treturn boolean
static int lunarssl_bn_is_odd(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_pushboolean(L, BN_is_odd(bn));
    return 1;
}

/// @function is_word
/// Returns true if the BIGNUM is equal to the given integer.
/// @tparam lunarssl.bn bn
/// @tparam integer word
/// @treturn boolean
static int lunarssl_bn_is_word(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BN_ULONG word = (BN_ULONG)luaL_checkinteger(L, 2);

    lua_pushboolean(L, BN_is_word(bn, word));
    return 1;
}

/// @function abs_is_word
/// Returns true if the absolute value of BIGNUM is equal to the absolute value of the given integer.
/// @tparam lunarssl.bn bn
/// @tparam integer word
/// @treturn boolean
static int lunarssl_bn_abs_is_word(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BN_ULONG word = (BN_ULONG)luaL_checkinteger(L, 2);

    lua_pushboolean(L, BN_abs_is_word(bn, word));
    return 1;
}

/// @function negate
/// Negates a BIGNUM. `bn = -bn`.
/// @tparam lunarssl.bn bn
static int lunarssl_bn_negate(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    LSSL_BN_negate(bn);
    return 0;
}

/// @function add
/// Adds two BIGNUMs. `r = a + b`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a addend
/// @tparam lunarssl.bn b addend
static int lunarssl_bn_add(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);

    LSSL_BN_CALL(BN_add, r, a, b);
    return 0;
}

/// @function sub
/// Subtracts two BIGNUMs. `r = a - b`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a subtrahend
/// @tparam lunarssl.bn b minuend
static int lunarssl_bn_sub(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);

    LSSL_BN_CALL(BN_sub, r, a, b);
    return 0;
}

/// @function mul
/// Multiplies two BIGNUMs. `r = a * b`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a multiplicand
/// @tparam lunarssl.bn b multiplier
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mul(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_mul, ctx, r, a, b);
    return 0;
}

/// @function sqr
/// Squares a BIGNUM. `r = a^2`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a base
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_sqr(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 3);

    LSSL_BNCTX_CALL(BN_sqr, ctx, r, a);
    return 0;
}

/// @function div
/// Divides two BIGNUMs. `r = a / b` and `rem = a % b`.
/// @tparam lunarssl.bn q quotient result location
/// @tparam lunarssl.bn r remainder result location
/// @tparam lunarssl.bn a dividend
/// @tparam lunarssl.bn b divisor
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_div(lua_State* L) {
    BIGNUM* q = lunarssl_bn_check(L, 1);
    BIGNUM* r = lunarssl_bn_check(L, 2);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 4);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 5);

    LSSL_BNCTX_CALL(BN_div, ctx, q, r, a, b);
    return 0;
}

/// @function mod
/// Calculates the remainder of a division. `rem = a % m`.
/// @tparam lunarssl.bn r remainder result location.
/// @tparam lunarssl.bn a dividend
/// @tparam lunarssl.bn m divisor
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_mod, ctx, r, a, m);
    return 0;
}

/// @function nnmod
/// Reduces a modulo m and returns the non-negative remainder.
/// @tparam lunarssl.bn r remainder result location.
/// @tparam lunarssl.bn a dividend
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_nnmod(lua_State* L) {
    BIGNUM* rem = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_nnmod, ctx, rem, a, m);
    return 0;
}

/// @function exp
/// Raises a BIGNUM to a power. `r = a^p`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a base
/// @tparam lunarssl.bn p exponent
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_exp(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* p = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_exp, ctx, r, a, p);
    return 0;
}

/// @function gcd
/// Calculates the greatest common divisor of two BIGNUMs. `r = gcd(a, b)`. `r` may alias `a` or `b`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a
/// @tparam lunarssl.bn b
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_gcd(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_gcd, ctx, r, a, b);
    return 0;
}

/// @function mod_add
/// Adds two BIGNUMs modulo m. `r = (a + b) mod m`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a addend
/// @tparam lunarssl.bn b addend
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_add(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 5);

    LSSL_BNCTX_CALL(BN_mod_add, ctx, r, a, b, m);
    return 0;
}

/// @function mod_sub
/// Subtracts two BIGNUMs modulo m. `r = (a - b) mod m`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a subtrahend
/// @tparam lunarssl.bn b minuend
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_sub(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 5);

    LSSL_BNCTX_CALL(BN_mod_sub, ctx, r, a, b, m);
    return 0;
}

/// @function mod_mul
/// Multiplies two BIGNUMs modulo m. `r = (a * b) mod m`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a multiplicand
/// @tparam lunarssl.bn b multiplier
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_mul(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* b = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 5);

    LSSL_BNCTX_CALL(BN_mod_mul, ctx, r, a, b, m);
    return 0;
}

/// @function mod_sqr
/// Squares a BIGNUM modulo m. `r = (a^2) mod m`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a base
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_sqr(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_mod_sqr, ctx, r, a, m);
    return 0;
}

/// @function mod_sqrt
/// Calculates the modular square root of a BIGNUM. `r^2 = a mod p`. `p` must be prime.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a radicand
/// @tparam lunarssl.bn p modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_sqrt(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* p = lunarssl_bn_check_loose(L, 3);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 4);

    LSSL_BNCTX_CALL(BN_mod_sqrt, ctx, r, a, p);
    return 0;
}

/// @function mod_exp
/// Raises a BIGNUM to a power modulo m. `r = a^p mod m`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a base
/// @tparam lunarssl.bn p exponent
/// @tparam lunarssl.bn m modulus
/// @tparam[opt] boolean secure use a secure context.
static int lunarssl_bn_mod_exp(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    const BIGNUM* p = lunarssl_bn_check_loose(L, 3);
    const BIGNUM* m = lunarssl_bn_check_loose(L, 4);
    BN_CTX* ctx = lunarssl_bn_ctx(L, 5);

    LSSL_BNCTX_CALL(BN_mod_exp, ctx, r, a, p, m);
    return 0;
}

/// @function add_word
/// Adds an integer to a BIGNUM. `r += a`.
/// @tparam lunarssl.bn r result location
/// @tparam integer a addend
static int lunarssl_bn_add_word(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0) {
        LSSL_BN_CALL(BN_sub_word, r, (BN_ULONG)-word);
    } else {
        LSSL_BN_CALL(BN_add_word, r, (BN_ULONG)word);
    }
    return 0;
}

/// @function sub_word
/// Subtracts an integer from a BIGNUM. `r -= a`.
/// @tparam lunarssl.bn r result location
/// @tparam integer a minuend
static int lunarssl_bn_sub_word(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0) {
        LSSL_BN_CALL(BN_add_word, r, (BN_ULONG)-word);
    } else {
        LSSL_BN_CALL(BN_sub_word, r, (BN_ULONG)word);
    }
    return 0;
}

/// @function mul_word
/// Multiplies a BIGNUM by an integer. `r *= a`.
/// @tparam lunarssl.bn r result location
/// @tparam integer a multiplier
static int lunarssl_bn_mul_word(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    lua_Integer word = luaL_checkinteger(L, 2);

    if (word < 0) {
        LSSL_BN_CALL(BN_mul_word, r, (BN_ULONG)-word);
        LSSL_BN_negate(r);
    } else {
        LSSL_BN_CALL(BN_mul_word, r, (BN_ULONG)word);
    }

    return 0;
}

/// @function div_word
/// Divides a BIGNUM by an integer and returns the remainder. `r /= a`.
/// @tparam lunarssl.bn r result location
/// @tparam integer a divisor
/// @treturn integer remainder
static int lunarssl_bn_div_word(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    lua_Integer word = luaL_checkinteger(L, 2);

    BN_ULONG rem;
    if (word < 0) {
        rem = BN_div_word(r, (BN_ULONG)-word);
        LSSL_BN_negate(r);
    } else {
        rem = BN_div_word(r, (BN_ULONG)word);
    }

    if (rem == (BN_ULONG)-1)
        return luaL_error(L, "BN_div_word failed: %s", LSSL_ERR_REASON);

    lua_pushinteger(L, (lua_Integer)rem);
    return 1;
}

/// @function mod_word
/// Calculates the remainder of a division by an unsigned word. `a % m`.
/// @tparam lunarssl.bn a dividend
/// @tparam integer m divisor
/// @treturn integer remainder
static int lunarssl_bn_mod_word(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    lua_Integer word = luaL_checkinteger(L, 2);

    BN_ULONG rem;
    if (word < 0) {
        rem = BN_mod_word(bn, (BN_ULONG)-word);
    } else {
        rem = BN_mod_word(bn, (BN_ULONG)word);
    }

    if (rem == (BN_ULONG)-1)
        return luaL_error(L, "BN_mod_word failed: %s", LSSL_ERR_REASON);

    lua_pushinteger(L, (lua_Integer)rem);
    return 1;
}

/// @function to_hex
/// Converts a BIGNUM to a hexadecimal string.
/// @tparam lunarssl.bn bn
/// @treturn string
static int lunarssl_bn_to_hex(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    char* hex = BN_bn2hex(bn);
    if (!hex)
        return luaL_error(L, "BN_bn2hex failed: %s", LSSL_ERR_REASON);

    lua_pushstring(L, hex);
    OPENSSL_free(hex);
    return 1;
}

/// @function to_dec
/// Converts a BIGNUM to a decimal string.
/// @tparam lunarssl.bn bn
/// @treturn string
static int lunarssl_bn_to_dec(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    char* dec = BN_bn2dec(bn);
    if (!dec)
        return luaL_error(L, "BN_bn2dec failed: %s", LSSL_ERR_REASON);

    lua_pushstring(L, dec);
    OPENSSL_free(dec);
    return 1;
}

/// @function to_bin
/// Converts a BIGNUM to a big-endian binary string.
/// @tparam lunarssl.bn bn
/// @tparam[opt] integer len number of bytes to output, or all of them if omitted.
/// @treturn string
static int lunarssl_bn_to_bin(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    size_t len = luaL_optinteger(L, 2, BN_num_bytes(bn));
    if (len <= 0)
        return luaL_error(L, "len must be positive");

    unsigned char* bin = (unsigned char*)OPENSSL_malloc(len);
    int written = BN_bn2binpad(bn, bin, len);
    if (written == -1) {
        OPENSSL_free(bin);
        return luaL_error(L, "BN_bn2binpad failed: %s", LSSL_ERR_REASON);
    }

    lua_pushlstring(L, (const char*)bin, written);
    OPENSSL_free(bin);
    return 1;
}

/// @function set_bit
/// Sets a bit in a BIGNUM. `a |= (1 << n)`
/// @tparam lunarssl.bn bn
/// @tparam integer bit index of the bit to set, starting at 0.
static int lunarssl_bn_set_bit(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    int bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    LSSL_BN_CALL(BN_set_bit, bn, bit);
    return 0;
}

/// @function clear_bit
/// Clears a bit in a BIGNUM. `a &= ~(1 << n)`
/// @tparam lunarssl.bn bn
/// @tparam integer bit index of the bit to clear, starting at 0.
static int lunarssl_bn_clear_bit(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    int bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    LSSL_BN_CALL(BN_clear_bit, bn, bit);
    return 0;
}

/// @function test_bit
/// Tests a bit in a BIGNUM.
/// @tparam lunarssl.bn bn
/// @tparam integer bit index of the bit to test, starting at 0.
/// @treturn boolean If the bit is set.
static int lunarssl_bn_test_bit(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    int bit = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bit >= 0, 2, "bit must be non-negative");

    lua_pushboolean(L, BN_is_bit_set(bn, bit));
    return 1;
}

/// @function mask_bits
/// Truncates a BIGNUM to a certain number of bits. `a &= ~((~0) << n))`.
///
/// Returns an error if the number is already small enough.
/// @tparam lunarssl.bn bn
/// @tparam integer bits number of low bits to keep.
static int lunarssl_bn_mask_bits(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    int bits = luaL_checkinteger(L, 2);
    luaL_argcheck(L, bits >= 0, 2, "bits must be non-negative");

    LSSL_BN_CALL(BN_mask_bits, bn, bits);
    return 0;
}

/// @function lshift
/// Shifts a BIGNUM left by a certain number of bits. `r = a << shamt`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a value
/// @tparam integer shamt number of bits to shift by
static int lunarssl_bn_lshift(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    int shamt = luaL_checkinteger(L, 3);
    luaL_argcheck(L, shamt >= 0, 2, "shamt must be non-negative");

    LSSL_BN_CALL(BN_lshift, r, a, shamt);
    return 0;
}

/// @function rshift
/// Shifts a BIGNUM right by a certain number of bits. `r = a >> shamt`.
/// @tparam lunarssl.bn r result location
/// @tparam lunarssl.bn a value
/// @tparam integer shamt number of bits to shift by
static int lunarssl_bn_rshift(lua_State* L) {
    BIGNUM* r = lunarssl_bn_check(L, 1);
    const BIGNUM* a = lunarssl_bn_check_loose(L, 2);
    int shamt = luaL_checkinteger(L, 3);
    luaL_argcheck(L, shamt >= 0, 2, "shamt must be non-negative");

    LSSL_BN_CALL(BN_rshift, r, a, shamt);
    return 0;
}

/// @function clear
/// Clears the BIGNUM and sets it to zero.
/// @tparam lunarssl.bn bn
static int lunarssl_bn_clear(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BN_clear(bn);
    return 0;
}

/// @function swap
/// Swaps two BIGNUMs.
/// @tparam lunarssl.bn a
/// @tparam lunarssl.bn b
static int lunarssl_bn_swap(lua_State* L) {
    BIGNUM* a = lunarssl_bn_check(L, 1);
    BIGNUM* b = lunarssl_bn_check(L, 2);
    BN_swap(a, b);
    return 0;
}

/// @function copy
/// Copies a BIGNUM.
/// @tparam lunarssl.bn from
/// @tparam lunarssl.bn to
static int lunarssl_bn_copy(lua_State* L) {
    BIGNUM* from = lunarssl_bn_check(L, 1);
    BIGNUM* to = lunarssl_bn_check(L, 2);

    LSSL_BN_CALL(BN_copy, to, from);
    return 0;
}

/// @function dup
/// Duplicates a BIGNUM.
/// @tparam lunarssl.bn bn
/// @treturn lunarssl.bn
static int lunarssl_bn_dup(lua_State* L) {
    BIGNUM* a = lunarssl_bn_check(L, 1);
    BIGNUM** bn = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));

    *bn = BN_dup(a);
    if (!*bn)
        return luaL_error(L, "BN_dup failed: %s", LSSL_ERR_REASON);

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

/// @function to_word
/// Converts a BIGNUM to an unsigned word or returns nil if it is too large.
/// @tparam lunarssl.bn bn
/// @treturn integer|nil
static int lunarssl_bn_to_word(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BN_ULONG word = BN_get_word(bn);
    if (word == (BN_ULONG)-1) {
        lua_pushnil(L);
        return 1;
    }

    if (BN_is_negative(bn))
        word = -word;

    lua_pushinteger(L, (lua_Integer)word);
    return 1;
}

static int lunarssl_bn__tostring(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    char* hex = BN_bn2hex(bn);
    if (!hex)
        return luaL_error(L, "BN_bn2hex failed: %s", LSSL_ERR_REASON);

    lua_pushfstring(L, "lunarssl.bn: %s", hex);
    OPENSSL_free(hex);
    return 1;
}

static int lunarssl_bn__add(lua_State* L) {
    if (lua_isinteger(L, 1) || lua_isinteger(L, 2)) {
        lua_Integer word;
        BIGNUM* bn;

        BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = BN_dup(bn);

        if (lua_isinteger(L, 1)) {
            word = luaL_checkinteger(L, 1);
            bn = lunarssl_bn_check(L, 2);
        } else {
            word = luaL_checkinteger(L, 2);
            bn = lunarssl_bn_check(L, 1);
        }

        if (word < 0) { // (-w) + b = b - w or b + (-w) = b - w
            LSSL_BNR_CALL(BN_sub_word, *r, (BN_ULONG)-word);
        } else { // w + b = b + w or b + w = b + w
            LSSL_BNR_CALL(BN_add_word, *r, (BN_ULONG)word);
        }
    } else {
        BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, 0);

        BIGNUM* a = lunarssl_bn_check(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        LSSL_BNR_CALL(BN_add, *r, a, b);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__sub(lua_State* L) {
    if (lua_isinteger(L, 1) || lua_isinteger(L, 2)) {
        lua_Integer word;
        BIGNUM* bn;

        if (lua_isinteger(L, 1)) {
            word = luaL_checkinteger(L, 1);
            bn = lunarssl_bn_check(L, 2);

            BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
            *r = BN_dup(bn);
            LSSL_BN_negate(*r);

            if (word < 0) { // (-w) - b = -b - w
                LSSL_BNR_CALL(BN_sub_word, *r, (BN_ULONG)-word);
            } else { // w - b = -b + w
                LSSL_BNR_CALL(BN_add_word, *r, (BN_ULONG)word);
            }
        } else {
            word = luaL_checkinteger(L, 2);
            bn = lunarssl_bn_check(L, 1);

            BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
            *r = BN_dup(bn);

            if (word < 0) { // b - (-w) = b + w
                LSSL_BNR_CALL(BN_add_word, *r, (BN_ULONG)-word);
            } else { // b - w = b - w
                LSSL_BNR_CALL(BN_sub_word, *r, (BN_ULONG)word);
            }
        }
    } else {
        BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = BN_new();

        BIGNUM* a = lunarssl_bn_check(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        LSSL_BNR_CALL(BN_sub, *r, a, b);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__mul(lua_State* L) {
    if (lua_isinteger(L, 1) || lua_isinteger(L, 2)) {
        lua_Integer word;
        BIGNUM* bn;

        if (lua_isinteger(L, 1)) {
            word = luaL_checkinteger(L, 1);
            bn = lunarssl_bn_check(L, 2);
        } else {
            word = luaL_checkinteger(L, 2);
            bn = lunarssl_bn_check(L, 1);
        }

        BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = BN_dup(bn);

        if (word < 0) {
            LSSL_BNR_CALL(BN_mul_word, *r, (BN_ULONG)-word);
            LSSL_BN_negate(*r);
        } else {
            LSSL_BNR_CALL(BN_mul_word, *r, (BN_ULONG)word);
        }
    } else {
        BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = BN_new();
        if (!*r)
            return luaL_error(L, "BN_new: %s", LSSL_ERR_REASON);

        BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
        BIGNUM* a = lunarssl_bn_check(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        LSSL_BNRCTX_CALL(BN_mul, *r, ctx, a, b);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__div(lua_State* L) {
    BIGNUM** r;

    if (lua_isinteger(L, 1)) {
        lua_Integer a = luaL_checkinteger(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, a);

        BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
        LSSL_BNRCTX_CALL(BN_div, *r, ctx, NULL, *r, b);
    } else if (lua_isinteger(L, 2)) {
        BIGNUM* a = lunarssl_bn_check(L, 1);
        lua_Integer b = luaL_checkinteger(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = BN_dup(a);

        if (b < 0) {
            LSSL_BNR_CALL(BN_div_word, *r, (BN_ULONG)-b);
            LSSL_BN_negate(*r);
        } else {
            LSSL_BNR_CALL(BN_div_word, *r, (BN_ULONG)b);
        }
    } else {
        BIGNUM* a = lunarssl_bn_check(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, 0);

        BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
        LSSL_BNRCTX_CALL(BN_div, *r, ctx, NULL, a, b);
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__mod(lua_State* L) {
    BIGNUM** r;
    int a_neg;
    int b_neg;

    if (lua_isinteger(L, 1)) {
        lua_Integer a = luaL_checkinteger(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, a);

        a_neg = a < 0;
        b_neg = BN_is_negative(b);

        BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
        if (!BN_div(NULL, *r, *r, b, ctx)) {
            BN_free(*r);
            BN_CTX_free(ctx);
            return luaL_error(L, "BN_div failed: %s", LSSL_ERR_REASON);
        }
        BN_CTX_free(ctx);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r)) {
            LSSL_BNR_CALL(BN_add, *r, *r, b);
        }
    } else if (lua_isinteger(L, 2)) {
        BIGNUM* a = lunarssl_bn_check(L, 1);
        lua_Integer b = luaL_checkinteger(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, 0);

        a_neg = BN_is_negative(a);
        b_neg = b < 0;

        BN_ULONG rem;
        if (b < 0) {
            rem = BN_mod_word(a, (BN_ULONG)-b);
        } else {
            rem = BN_mod_word(a, (BN_ULONG)b);
        }

        if (rem == (BN_ULONG)-1) {
            BN_free(*r);
            return luaL_error(L, "BN_mod_word failed: %s", LSSL_ERR_REASON);
        }

        LSSL_BNR_CALL(BN_set_word, *r, rem);
        if (a_neg)
            LSSL_BN_negate(*r);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r)) {
            BIGNUM* bn = lunarssl_bn_create(L, 0, b);
            LSSL_BNR_CALL(BN_add, *r, *r, bn);
        }
    } else {
        BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
        BIGNUM* a = lunarssl_bn_check(L, 1);
        BIGNUM* b = lunarssl_bn_check(L, 2);

        r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
        *r = lunarssl_bn_create(L, 0, 0);

        a_neg = BN_is_negative(a);
        b_neg = BN_is_negative(b);

        LSSL_BNRCTX_CALL(BN_mod, *r, ctx, a, b);

        // convert remainder into modulo
        BN_set_negative(*r, a_neg);
        if (a_neg != b_neg && !BN_is_zero(*r)) {
            LSSL_BNR_CALL(BN_add, *r, *r, b);
        }
    }

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__pow(lua_State* L) {
    BIGNUM* a;
    BIGNUM* p;

    if (lua_isinteger(L, 1)) {
        a = lunarssl_bn_create(L, 0, luaL_checkinteger(L, 1));
    } else {
        a = lunarssl_bn_check(L, 1);
    }

    if (lua_isinteger(L, 2)) {
        p = lunarssl_bn_create(L, 0, luaL_checkinteger(L, 2));
    } else {
        p = lunarssl_bn_check(L, 2);
    }

    BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *r = BN_new();

    BN_CTX* ctx = lunarssl_bn_ctx(L, -1);
    LSSL_BNRCTX_CALL(BN_exp, *r, ctx, a, p);

    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__unm(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BIGNUM** r = (BIGNUM**)lua_newuserdata(L, sizeof(BIGNUM*));
    *r = BN_dup(bn);
    if (!*r)
        return luaL_error(L, "BN_dup: %s", LSSL_ERR_REASON);

    LSSL_BN_negate(*r);
    luaL_setmetatable(L, "lunarssl.bn");
    return 1;
}

static int lunarssl_bn__eq(lua_State* L) {
    BIGNUM* a = lunarssl_bn_check(L, 1);
    BIGNUM* b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) == 0);
    return 1;
}

static int lunarssl_bn__lt(lua_State* L) {
    BIGNUM* a = lunarssl_bn_check(L, 1);
    BIGNUM* b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) < 0);
    return 1;
}

static int lunarssl_bn__le(lua_State* L) {
    BIGNUM* a = lunarssl_bn_check(L, 1);
    BIGNUM* b = lunarssl_bn_check(L, 2);
    lua_pushboolean(L, BN_cmp(a, b) <= 0);
    return 1;
}

static int lunarssl_bn__gc(lua_State* L) {
    BIGNUM* bn = lunarssl_bn_check(L, 1);
    BN_free(bn);
    return 0;
}

luaL_Reg lib_lunarssl_bn[] = {
    { "new", lunarssl_bn_new },
    { "from_hex", lunarssl_bn_from_hex },
    { "from_dec", lunarssl_bn_from_dec },
    { "from_bin", lunarssl_bn_from_bin },
    { NULL, NULL }
};

luaL_Reg lib_lunarssl_bn_method[] = {
    { "num_bytes", lunarssl_bn_num_bytes },
    { "num_bits", lunarssl_bn_num_bits },
    { "cmp", lunarssl_bn_cmp },
    { "ucmp", lunarssl_bn_ucmp },
    { "is_zero", lunarssl_bn_is_zero },
    { "is_one", lunarssl_bn_is_one },
    { "is_odd", lunarssl_bn_is_odd },
    { "is_word", lunarssl_bn_is_word },
    { "is_negative", lunarssl_bn_is_negative },
    { "abs_is_word", lunarssl_bn_abs_is_word },
    { "negate", lunarssl_bn_negate },
    { "add", lunarssl_bn_add },
    { "sub", lunarssl_bn_sub },
    { "mul", lunarssl_bn_mul },
    { "sqr", lunarssl_bn_sqr },
    { "div", lunarssl_bn_div },
    { "mod", lunarssl_bn_mod },
    { "nnmod", lunarssl_bn_nnmod },
    { "exp", lunarssl_bn_exp },
    { "gcd", lunarssl_bn_gcd },
    { "mod_add", lunarssl_bn_mod_add },
    { "mod_sub", lunarssl_bn_mod_sub },
    { "mod_mul", lunarssl_bn_mod_mul },
    { "mod_sqr", lunarssl_bn_mod_sqr },
    { "mod_sqrt", lunarssl_bn_mod_sqrt },
    { "mod_exp", lunarssl_bn_mod_exp },
    { "add_word", lunarssl_bn_add_word },
    { "sub_word", lunarssl_bn_sub_word },
    { "mul_word", lunarssl_bn_mul_word },
    { "div_word", lunarssl_bn_div_word },
    { "mod_word", lunarssl_bn_mod_word },
    { "to_hex", lunarssl_bn_to_hex },
    { "to_dec", lunarssl_bn_to_dec },
    { "to_bin", lunarssl_bn_to_bin },
    { "to_word", lunarssl_bn_to_word },
    { "set_bit", lunarssl_bn_set_bit },
    { "clear_bit", lunarssl_bn_clear_bit },
    { "test_bit", lunarssl_bn_test_bit },
    { "mask_bits", lunarssl_bn_mask_bits },
    { "lshift", lunarssl_bn_lshift },
    { "rshift", lunarssl_bn_rshift },
    { "clear", lunarssl_bn_clear },
    { "swap", lunarssl_bn_swap },
    { "copy", lunarssl_bn_copy },
    { "dup", lunarssl_bn_dup },
    { NULL, NULL }
};

luaL_Reg lib_lunarssl_bn_mt[] = {
    { "__tostring", lunarssl_bn__tostring },
    { "__add", lunarssl_bn__add },
    { "__sub", lunarssl_bn__sub },
    { "__mul", lunarssl_bn__mul },
    { "__div", lunarssl_bn__div },
    { "__idiv", lunarssl_bn__div },
    { "__mod", lunarssl_bn__mod },
    { "__pow", lunarssl_bn__pow },
    { "__unm", lunarssl_bn__unm },
    { "__eq", lunarssl_bn__eq },
    { "__lt", lunarssl_bn__lt },
    { "__le", lunarssl_bn__le },
    { "__gc", lunarssl_bn__gc },
    { NULL, NULL }
};

int luaopen_lunarssl_bn(lua_State* L) {
    luaL_newmetatable(L, "lunarssl.bn");
    luaL_setfuncs(L, lib_lunarssl_bn_mt, 0);
    luaL_setfuncs(L, lib_lunarssl_bn_method, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);

    luaL_newlib(L, lib_lunarssl_bn);
    luaL_setfuncs(L, lib_lunarssl_bn_method, 0);
    return 1;
}
