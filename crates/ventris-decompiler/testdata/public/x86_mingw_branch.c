uint32_t sub_1000(void)
{
    *(uint64_t *)(uintptr_t)(rsp - 8) = rbp;
    *(uint64_t *)(uintptr_t)(rsp - 8 - 8) = rax;
    *(uint32_t *)(uintptr_t)(rsp - 8 - 8 + 4) = rcx;
    *(uint32_t *)(uintptr_t)(rsp - 8 - 8) = *(uint32_t *)(uintptr_t)(rsp - 8 - 8 + 4);
    if ((*(uint32_t *)(uintptr_t)(rsp - 8 - 8 + 4) & 1) - 0 == 0) {
        *(uint32_t *)(uintptr_t)(rsp - 8 - 8) = *(uint32_t *)(uintptr_t)(rsp - 8 - 8) - 2;
    } else {
        *(uint32_t *)(uintptr_t)(rsp - 8 - 8) = *(uint32_t *)(uintptr_t)(rsp - 8 - 8) + 3;
    }
    return *(uint32_t *)(uintptr_t)(rsp - 8 - 8);
}
