#include <stdint.h>

__attribute__((noinline)) uint32_t add_numbers(uint32_t left, uint32_t right) {
    return left + right;
}

int main(void) {
    return (int)add_numbers(2, 3);
}
