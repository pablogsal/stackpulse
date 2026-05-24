#include "test_target.h"

#include <stdlib.h>

void stackpulse_shared_entry(void);

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    stackpulse_notify_ready(atoi(argv[1]));
    stackpulse_shared_entry();
    return 0;
}
