#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rtgum/kpm_supercall.h>

#define MODULE_NAME "rtgum-stage1-probe"

static int contains_module(const char *names)
{
    const size_t wanted = strlen(MODULE_NAME);
    const char *cursor = names;
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length == wanted && !memcmp(cursor, MODULE_NAME, wanted)) return 1;
        if (!end) break;
        cursor = end + 1;
    }
    return 0;
}

static int run_probe(const char *key, const char *module_path)
{
    struct rtgum_kpm_load_result detail = { 0 };
    cpu_set_t allowed, single;
    char names[1024] = { 0 };
    char response[512];
    long result;
    int loaded = 0;
    int pinned = 0;
    int count = 0;
    int status = 1;

    result = rtgum_sc_hello(key);
    if (result != RTGUM_SUPERCALL_HELLO_MAGIC || rtgum_sc_kp_ver(key) != 0xd09U) {
        fprintf(stderr, "KernelPatch 0.13.9 SuperCall is unavailable\n");
        return 1;
    }
    result = rtgum_sc_kpm_list(key, names, sizeof(names));
    if (result < 0) {
        fprintf(stderr, "KPM list failed: %ld\n", result);
        return 1;
    }
    if (contains_module(names)) {
        fprintf(stderr, "probe KPM is already loaded; run unload first\n");
        return 1;
    }

    detail.magic = RTGUM_KPM_LOAD_RESULT_MAGIC;
    detail.size = sizeof(detail);
    result = rtgum_sc_kpm_load(key, module_path, "probe", &detail);
    if (result != 0) {
        fprintf(stderr, "probe KPM load failed: result=%ld detail=%s\n",
                result, detail.message[0] ? detail.message : "unavailable");
        return 1;
    }
    loaded = 1;

    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        fprintf(stderr, "sched_getaffinity failed: %s\n", strerror(errno));
        goto cleanup;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed)) continue;
        CPU_ZERO(&single);
        CPU_SET(cpu, &single);
        if (sched_setaffinity(0, sizeof(single), &single) != 0) {
            fprintf(stderr, "sched_setaffinity cpu=%d failed: %s\n", cpu, strerror(errno));
            goto cleanup;
        }
        pinned = 1;
        memset(response, 0, sizeof(response));
        result = rtgum_sc_kpm_control(key, MODULE_NAME, "probe", response, sizeof(response));
        if (result != 0 || response[0] == '\0') {
            fprintf(stderr, "KPM probe failed on cpu=%d: result=%ld\n", cpu, result);
            goto cleanup;
        }
        printf("cpu=%d %s\n", cpu, response);
        ++count;
    }
    if (count == 0) {
        fprintf(stderr, "No CPU was available for probing\n");
        goto cleanup;
    }
    status = 0;

cleanup:
    if (pinned && sched_setaffinity(0, sizeof(allowed), &allowed) != 0) {
        fprintf(stderr, "restore affinity failed: %s\n", strerror(errno));
        status = 1;
    }
    if (loaded) {
        result = rtgum_sc_kpm_unload(key, MODULE_NAME);
        if (result != 0) {
            fprintf(stderr, "probe KPM unload failed: result=%ld\n", result);
            status = 1;
        }
    }
    if (status == 0) printf("probe PASS cpus=%d unloaded=1\n", count);
    return status;
}

int main(int argc, char **argv)
{
    const char *key = getenv("RTGUM_SUPERKEY");
    long result;

    if (!key || !key[0] || strnlen(key, RTGUM_SUPERCALL_KEY_MAX_LEN) >=
                           RTGUM_SUPERCALL_KEY_MAX_LEN) {
        fprintf(stderr, "RTGUM_SUPERKEY is missing or invalid\n");
        return 2;
    }
    if (argc == 3 && !strcmp(argv[1], "run")) return run_probe(key, argv[2]);
    if (argc == 2 && !strcmp(argv[1], "unload")) {
        result = rtgum_sc_kpm_unload(key, MODULE_NAME);
        if (result != 0) {
            fprintf(stderr, "probe KPM unload failed: result=%ld\n", result);
            return 1;
        }
        puts("probe KPM unloaded");
        return 0;
    }
    fprintf(stderr, "Usage: RTGUM_SUPERKEY=<key> %s run <probe.kpm> | unload\n", argv[0]);
    return 2;
}
