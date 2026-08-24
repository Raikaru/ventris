void sub_1000(void)
{
    *(uint16_t *)(uintptr_t)(gp - 0x47e6) = 0;
    *(uint16_t *)(uintptr_t)(gp - 0x47e4) = a0;
    *(uint8_t *)(uintptr_t)(gp - 0x47e8) = 1;
    return;
}
