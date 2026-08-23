uint32_t sub_1000(void)
{
    *(uint64_t *)(uintptr_t)(rsp - 8) = rbp;
    *(uint32_t *)(uintptr_t)(rsp - 8 + 0x10) = rcx;
    *(uint32_t *)(uintptr_t)(rsp - 8 + 0x18) = rdx;
    return *(uint32_t *)(uintptr_t)(rsp - 8 + 0x18) + *(uint32_t *)(uintptr_t)(rsp - 8 + 0x10);
}
