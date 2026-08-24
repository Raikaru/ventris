/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * The same EABI bytes are exercised under both GameCube and Wii profiles.
 */
#include <stdint.h>

uint32_t abi_gap_fill(uint32_t first, uint32_t skipped, uint32_t third)
{
    return first + third;
}
