/* Tiny x86-32 PE fixture with function-pointer table.
   Compiled with:
   i686-w64-mingw32-gcc -O2 -o tiny_pe32.exe tiny_pe32.c */
#include <stdio.h>

typedef int (*calc_fn)(int);
static int f_double(int x) { return x * 2; }
static int f_square(int x) { return x * x; }
static calc_fn dispatch_table[] = { f_double, f_square };

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("%d\n", dispatch_table[argc % 2](argc));
    }
    return 0;
}
