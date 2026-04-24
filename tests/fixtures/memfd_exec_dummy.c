#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

int main() {
    /* read /bin/true as "payload" */
    int src = open("/bin/true", O_RDONLY);
    if (src <0) { perror("open"); return 1; }

    off_t size = lseek(src, 0, SEEK_END);
    lseek(src, 0, SEEK_SET);

    char *buf = malloc(size);
    read(src, buf, size);
    close(src);

    /* create anonymous in-memory file  */
    int fd = syscall(SYS_memfd_create, "test", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }

    write(fd, buf, size);
    free(buf);

    /* execute from memory - nothing on disk */
    char *argv[] = { "memfd_test", NULL };
    char *envp[] = { NULL };
    syscall(SYS_execveat, fd, "", argv, envp, 0x1000); // AT_EMPTY_PATH

    perror("execveat");
    return 1;
}
