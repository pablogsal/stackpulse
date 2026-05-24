#include "test_target.h"

#include <stdint.h>
#include <stdlib.h>

volatile int stackpulse_c_stop = 0;

__attribute__((noinline)) void stackpulse_c_leaf(void) {
    volatile uint64_t value = 1;
    while (!stackpulse_c_stop) {
        value = value * 33 + 17;
    }
}

__attribute__((noinline)) void stackpulse_c_middle(void) {
    stackpulse_c_leaf();
    stackpulse_c_stop = 1;
}

__attribute__((noinline)) void stackpulse_c_entry(void) {
    stackpulse_c_middle();
    stackpulse_c_stop = 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    stackpulse_notify_ready(atoi(argv[1]));
    stackpulse_c_entry();
    return 0;
}
