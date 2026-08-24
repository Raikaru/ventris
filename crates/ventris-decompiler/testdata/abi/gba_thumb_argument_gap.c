/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * ARM7TDMI Thumb uses the third integer argument while skipping the second.
 */
#include <stdint.h>

uint32_t abi_gap_fill(uint32_t first, uint32_t skipped, uint32_t third)
{
    return first + third;
}
