/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * The ninth EABI integer argument follows the r3-r10 register prefix.
 */
#include <stdint.h>

uint32_t abi_stack_overflow(
    uint32_t first,
    uint32_t second,
    uint32_t third,
    uint32_t fourth,
    uint32_t fifth,
    uint32_t sixth,
    uint32_t seventh,
    uint32_t eighth,
    uint32_t overflow)
{
    return first + overflow;
}
