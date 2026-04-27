#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t child = fork();

    if (child == 0) {
        sleep(5);
        return 0;
    }

    sleep(1);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);

    /* open with write access — triggers detection */
    int fd = open(path, O_WRONLY);
    if (fd >= 0)
        close(fd);

    kill(child, 9);
    return 0;
}
