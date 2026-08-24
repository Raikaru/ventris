/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * The fifth soft-float AAPCS32 argument follows the r0-r3 register prefix.
 */
#include <stdint.h>

uint32_t abi_stack_overflow(
    uint32_t first,
    uint32_t second,
    uint32_t third,
    uint32_t fourth,
    uint32_t overflow)
{
    return first + overflow;
}
