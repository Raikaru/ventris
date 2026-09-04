/* Dispatch PE fixture with function-pointer table in .data/.rdata.
   Compiled with:
   x86_64-w64-mingw32-gcc -O2 -o dispatch.exe dispatch.c */
#include <stdio.h>

typedef int (*calc_fn)(int);
static int f_double(int x) { return x * 2; }
static int f_square(int x) { return x * x; }
static int f_cube(int x) { return x * x * x; }
static calc_fn dispatch_table[] = { f_double, f_square, f_cube };

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("%d\n", dispatch_table[argc % 3](argc));
    }
    return 0;
}
