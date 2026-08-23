#include <stdint.h>
#include <stdbool.h>

void sub_8000554(void)
{
    *(volatile uint16_t *)(uintptr_t)(0x4000106) = 0x80;
    return;
}
