#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t child = fork();

    if (child == 0) {
        sleep(5);
        return 0;
    }

    sleep(1);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
        perror("ptrace attach");
        kill(child, 9);
        return 1;
    }

    printf("attached to %d\n", child);
    waitpid(child, NULL, 0);

    ptrace(PTRACE_DETACH, child, NULL, NULL);
    kill(child, 9);
    return 0;
}
