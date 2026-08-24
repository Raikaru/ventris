void sub_1000(void)
{
    *(uint16_t *)(uintptr_t)(gp + 0xffffb81a) = 0;
    *(uint16_t *)(uintptr_t)(gp + 0xffffb81c) = a0;
    *(uint8_t *)(uintptr_t)(gp + 0xffffb818) = 1;
    return;
}
