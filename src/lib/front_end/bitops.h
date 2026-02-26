/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2017-2019, 2023 NXP
 */

#ifndef BITOPS_H
#define BITOPS_H

#include <stdint.h>

#define BIT(x)  (1UL << (x))

/* Generate a bitmask starting at index s, ending at index e */
#define BIT_MASK(e, s) ((((1UL) << (e - s + 1)) - 1) << s)

static inline uint8_t bf_get_uint8(uint32_t w, uint32_t m, uint8_t s)
{
    return (uint8_t) ((w & m) >> s);
}

static inline uint16_t bf_get_uint16(uint32_t w, uint32_t m, uint8_t s)
{
    return (uint16_t) ((w & m) >> s);
}

static inline uint32_t bf_get_uint32(uint32_t w, uint32_t m, uint8_t s)
{
    return (uint32_t) ((w & m) >> s);
}

static inline uint32_t bf_popcount(uint32_t x)
{
    return (uint32_t) (__builtin_popcount(x));
}

static inline uint32_t bf_ffs(uint32_t x)
{
    return (uint32_t) (__builtin_ffs(x));
}
#endif /* BITOPS_H */
