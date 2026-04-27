#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/wait.h>

int main() {
    char buf[] = "hello";
    pid_t child = fork();

    if (child == 0) {
        sleep(5);
        return 0;
    }

    sleep (1);

    struct iovec local = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct iovec remote = { .iov_base = NULL, .iov_len = sizeof(buf) };

    process_vm_writev(child, &local, 1, &remote, 1, 0);

    kill(child, 9);
    return 0;
}
