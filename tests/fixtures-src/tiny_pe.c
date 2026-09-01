/* Tiny x86-64 PE fixture, compiled with:
   x86_64-w64-mingw32-gcc -O0 -o tiny_pe.exe tiny_pe.c */
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { printf("%d\n", add(2, 40)); return 0; }
