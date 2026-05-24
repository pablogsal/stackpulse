#include "test_target.h"

#include <stdint.h>
#include <stdlib.h>

volatile int stackpulse_recursive_stop = 0;

__attribute__((noinline)) void stackpulse_c_recursive_leaf(void) {
    volatile uint64_t value = 5;
    while (!stackpulse_recursive_stop) {
        value = value * 41 + 11;
    }
}

__attribute__((noinline)) void stackpulse_c_recursive(int depth) {
    volatile int marker = depth;
    if (depth == 0) {
        stackpulse_c_recursive_leaf();
    } else {
        stackpulse_c_recursive(depth - 1);
    }
    if (marker == -1) {
        stackpulse_recursive_stop = 1;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    stackpulse_notify_ready(atoi(argv[1]));
    stackpulse_c_recursive(6);
    return 0;
}
