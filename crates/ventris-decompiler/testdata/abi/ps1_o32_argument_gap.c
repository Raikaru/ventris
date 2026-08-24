/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * The third O32 integer argument is used while the first two are skipped.
 */
#include <stdint.h>

uint32_t abi_gap_fill(uint32_t first, uint32_t skipped, uint32_t third)
{
    return third + 1u;
}
