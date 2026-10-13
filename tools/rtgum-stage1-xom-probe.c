/* SPDX-License-Identifier: MIT */
/* EL0 VMA permission probe; it never edits page tables directly. */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void child_fault(int signal_number)
{
    _exit(100 + signal_number);
}

static int child_result(void *page, int execute)
{
    pid_t child = fork();
    int status = 0;
    if (child < 0) return -1;
    if (child == 0) {
        struct sigaction handler = { 0 };
        handler.sa_handler = child_fault;
        sigemptyset(&handler.sa_mask);
        sigaction(SIGSEGV, &handler, NULL);
        sigaction(SIGBUS, &handler, NULL);
        sigaction(SIGILL, &handler, NULL);
        if (execute) {
            int (*code)(void) = (int (*)(void))page;
            _exit(code() == 42 ? 0 : 1);
        }
        volatile unsigned char value = *(volatile unsigned char *)page;
        _exit(value == 0x40 ? 0 : 1);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int main(void)
{
#if !defined(__aarch64__)
    fputs("requires AArch64\n", stderr);
    return 2;
#else
    const long page_size = sysconf(_SC_PAGESIZE);
    const uint32_t code[] = { 0x52800540U, 0xd65f03c0U }; /* mov w0,#42; ret */
    void *page;
    int exec_result, xom_read_result, rx_read_result;

    if (page_size <= 0) return 2;
    page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 2;
    }
    memcpy(page, code, sizeof(code));
    __builtin___clear_cache((char *)page, (char *)page + sizeof(code));
    if (mprotect(page, (size_t)page_size, PROT_EXEC) != 0) {
        fprintf(stderr, "mprotect(PROT_EXEC): %s\n", strerror(errno));
        munmap(page, (size_t)page_size);
        return 2;
    }
    exec_result = child_result(page, 1);
    xom_read_result = child_result(page, 0);
    if (mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "mprotect(PROT_READ|PROT_EXEC): %s\n", strerror(errno));
        munmap(page, (size_t)page_size);
        return 2;
    }
    rx_read_result = child_result(page, 0);
    munmap(page, (size_t)page_size);

    printf("el0_vma_xom execute=%s read=%s rx_read=%s raw=%d,%d,%d\n",
           exec_result == 0 ? "pass" : "fail",
           xom_read_result == 100 + SIGSEGV ? "sigsegv" : "unexpected",
           rx_read_result == 0 ? "pass" : "fail",
           exec_result, xom_read_result, rx_read_result);
    return exec_result == 0 && xom_read_result == 100 + SIGSEGV &&
                   rx_read_result == 0 ? 0 : 1;
#endif
}
