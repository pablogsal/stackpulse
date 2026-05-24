#include <stdint.h>

volatile int stackpulse_shared_stop = 0;

__attribute__((noinline)) void stackpulse_shared_leaf(void) {
    volatile uint64_t value = 9;
    while (!stackpulse_shared_stop) {
        value = value * 37 + 23;
    }
}

__attribute__((noinline)) void stackpulse_shared_middle(void) {
    stackpulse_shared_leaf();
    stackpulse_shared_stop = 1;
}

__attribute__((noinline)) void stackpulse_shared_entry(void) {
    stackpulse_shared_middle();
    stackpulse_shared_stop = 1;
}
