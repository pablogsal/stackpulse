#include "test_target.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

volatile int stackpulse_kernel_stop = 0;

__attribute__((noinline)) void stackpulse_kernel_syscall_leaf(void) {
    char buffer[4096];
    while (!stackpulse_kernel_stop) {
        int fd = open("/proc/self/stat", O_RDONLY);
        if (fd >= 0) {
            (void)read(fd, buffer, sizeof(buffer));
            close(fd);
        }
    }
}

__attribute__((noinline)) void stackpulse_kernel_syscall_entry(void) {
    stackpulse_kernel_syscall_leaf();
    stackpulse_kernel_stop = 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    stackpulse_notify_ready(atoi(argv[1]));
    stackpulse_kernel_syscall_entry();
    return 0;
}
