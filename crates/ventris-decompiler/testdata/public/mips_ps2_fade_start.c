void sub_1000(void)
{
    *(uint16_t *)(uintptr_t)(gp + 0xffffffffffffb81a) = 0;
    *(uint16_t *)(uintptr_t)(gp + 0xffffffffffffb81c) = a0;
    *(bool *)(uintptr_t)(gp + 0xffffffffffffb818) = 1;
    return;
}
