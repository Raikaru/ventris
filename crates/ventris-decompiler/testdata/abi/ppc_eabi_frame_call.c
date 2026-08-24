/*
 * Authored, redistributable ABI fixture; no game-derived material.
 * Exercises a non-leaf EABI frame, LR/callee-save preservation, register copy,
 * indirect call through CTR, and restoration of the original first argument.
 */
#include <stdint.h>

__attribute__((noinline)) uint32_t ppc_frame_call(
    uint32_t first,
    uint32_t second,
    uint32_t third,
    void (*sink)(uint32_t, uint32_t, uint32_t))
{
    uint32_t saved = first;
    sink(first, second, third);
    return saved;
}
