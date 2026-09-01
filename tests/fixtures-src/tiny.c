/* Tiny x86-64 ELF fixture, compiled with: gcc -O0 -o tiny_bin tiny.c */
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { printf("%d\n", add(2, 40)); return 0; }
