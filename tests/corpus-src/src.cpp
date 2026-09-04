#include <stdio.h>

thread_local int tls_var = 42;

// Portable minimal exception personality and runtime stubs for cross-sysroot builds
extern "C" {
    void* __cxa_allocate_exception(unsigned long) { return (void*)0; }
    void __cxa_throw(void*, void*, void*) { while(1); }
    void* __cxa_begin_catch(void*) { return (void*)0; }
    void __cxa_end_catch() {}
    int __gxx_personality_v0() { return 0; }
}

int compute(int x) {
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        case 5: return 50;
        case 6: return 60;
        case 7: return 70;
        case 8: return 80;
        default: return -1;
    }
}

int do_work(int x) {
    if (x < 0) {
        throw 1;
    }
    return compute(x) + tls_var;
}

int main(int argc, char **argv) {
    try {
        printf("res: %d\n", do_work(argc));
    } catch (...) {
        return 1;
    }
    return 0;
}
