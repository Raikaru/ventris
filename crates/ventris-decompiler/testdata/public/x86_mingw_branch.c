uint32_t sub_1000(void)
{
    *(uint64_t *)(uintptr_t)(rsp - 8) = rbp;
    *(uint64_t *)(uintptr_t)(rsp - 0x10) = rax;
    *(uint32_t *)(uintptr_t)(rsp - 0xc) = rcx;
    *(uint32_t *)(uintptr_t)(rsp - 0x10) = *(uint32_t *)(uintptr_t)(rsp - 0xc);
    if ((*(uint32_t *)(uintptr_t)(rsp - 0xc) & 1) == 0) {
        *(uint32_t *)(uintptr_t)(rsp - 0x10) = *(uint32_t *)(uintptr_t)(rsp - 0x10) - 2;
    } else {
        *(uint32_t *)(uintptr_t)(rsp - 0x10) = *(uint32_t *)(uintptr_t)(rsp - 0x10) + 3;
    }
    return *(uint32_t *)(uintptr_t)(rsp - 0x10);
}
