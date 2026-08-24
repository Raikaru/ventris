/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * The fifth O32 argument overflows the four-register argument prefix.
 */
#include <stdint.h>

uint32_t abi_stack_overflow(
    uint32_t first,
    uint32_t skipped,
    uint32_t third,
    uint32_t skipped_stack_prefix,
    uint32_t overflow)
{
    return third + overflow;
}
