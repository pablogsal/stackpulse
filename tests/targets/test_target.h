#ifndef STACKPULSE_TEST_TARGET_H
#define STACKPULSE_TEST_TARGET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void stackpulse_notify_ready(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(2);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        perror("inet_pton");
        exit(2);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        exit(2);
    }

    char line[64];
    int len = snprintf(line, sizeof(line), "ready:%ld\n", (long)getpid());
    if (len <= 0 || write(sock, line, (size_t)len) != len) {
        perror("write");
        exit(2);
    }
    close(sock);
}

#endif
