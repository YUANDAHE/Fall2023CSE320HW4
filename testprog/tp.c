#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <execinfo.h>

void a(int x);
void b(int x);
void c(int x);
void d(int x);
void e(int x);
void f(void);

unsigned long static_variable;

int main(int argc, char *argv[]) {
    a(666);
}

void a(int x) {
    fprintf(stderr, "function a @ %p, argument x @ %p (=%d)\n", a, &x, x);
    b(x+1);
}

void b(int x) {
    fprintf(stderr, "function b @ %p: argument x @ %p (=%d)\n", b, &x, x);
    c(x+1);
}

void c(int x) {
    fprintf(stderr, "function c @ %p: argument x @ %p (=%d)\n", c, &x, x);
    d(x+1);
}

void d(int x) {
    fprintf(stderr, "function d @ %p: argument x @ %p (=%d)\n", d, &x, x);
    e(x+1);
}

void e(int x) {
    fprintf(stderr, "function e @ %p: argument x @ %p (=%d)\n", e, &x, x);
    while(1) {
	f();
	kill(getpid(), SIGSTOP);
    }
#if 0
    void *buf[10];
    int n = backtrace(buf, sizeof(buf)/sizeof(void *));
    char **syms = backtrace_symbols(buf, n);
    for(int i = 0; i < n; i++)
	fprintf(stderr, "%d:\t%p (%s)\n", i, buf[i], syms[i]);
#endif
}

void f(void) {
    unsigned long local_variable;
    fprintf(stderr, "function f @ %p called\n", f);
    fprintf(stderr, "static_variable @ %p (=%lx)\n", &static_variable, static_variable);
    fprintf(stderr, "local_variable @ %p (=%lx)\n", &local_variable, local_variable);
}
