#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rtgum/kpm_supercall.h>

#define MODULE_NAME "rtgum-stage0"
#define CONTROL_BUFFER_SIZE 256
#define STAGE0_PAGE_SIZE 4096UL

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: RTGUM_SUPERKEY=<key> %s <command> [module.kpm]\n"
            "Commands:\n"
            "  ready                 check the KernelPatch supercall\n"
            "  load <module.kpm>     load the stage-0 KPM\n"
            "  ping                  perform a KPM control round-trip\n"
            "  alloc                 allocate and verify one anonymous page\n"
            "  list                  list loaded KPM names\n"
            "  info                  show stage-0 KPM metadata\n"
            "  dmesg                 temporarily elevate this process and read dmesg\n"
            "  unload                unload the stage-0 KPM\n"
            "  smoke <module.kpm>    ready + load/reuse + ping + alloc\n",
            program);
}

static const char *require_key(void)
{
    const char *key = getenv("RTGUM_SUPERKEY");
    if (!key || key[0] == '\0') {
        fprintf(stderr, "RTGUM_SUPERKEY is required\n");
        return NULL;
    }
    if (strnlen(key, RTGUM_SUPERCALL_KEY_MAX_LEN) >= RTGUM_SUPERCALL_KEY_MAX_LEN) {
        fprintf(stderr, "RTGUM_SUPERKEY is too long\n");
        return NULL;
    }
    return key;
}

static int report_call_error(const char *operation, long result)
{
    if (result == -1) {
        fprintf(stderr, "%s failed: errno=%d (%s)\n", operation, errno, strerror(errno));
    } else {
        fprintf(stderr, "%s failed: result=%ld\n", operation, result);
    }
    return 1;
}

static int command_ready(const char *key)
{
    long hello = rtgum_sc_hello(key);
    if (hello != RTGUM_SUPERCALL_HELLO_MAGIC) return report_call_error("supercall hello", hello);

    printf("ready hello=0x%lx kpver=0x%x kver=0x%x\n",
           hello,
           rtgum_sc_kp_ver(key),
           rtgum_sc_k_ver(key));
    return 0;
}

static int command_load(const char *key, const char *path)
{
    struct rtgum_kpm_load_result detail;
    long result;

    memset(&detail, 0, sizeof(detail));
    detail.magic = RTGUM_KPM_LOAD_RESULT_MAGIC;
    detail.size = sizeof(detail);
    result = rtgum_sc_kpm_load(key, path, "stage0", &detail);

    if (result != 0) {
        if (detail.magic == RTGUM_KPM_LOAD_RESULT_MAGIC && detail.message[0] != '\0') {
            fprintf(stderr, "KPM load detail: code=%d message=%s\n", detail.code, detail.message);
        }
        return report_call_error("KPM load", result);
    }

    printf("loaded module=%s path=%s detail=%s\n",
           MODULE_NAME,
           path,
           detail.message[0] ? detail.message : "not-reported");
    return 0;
}

static int control(const char *key, const char *command, char *response, size_t response_size)
{
    long result;

    memset(response, 0, response_size);
    result = rtgum_sc_kpm_control(key, MODULE_NAME, command, response, (long)response_size);
    if (result != 0) return report_call_error("KPM control", result);
    if (response[0] == '\0') {
        fprintf(stderr, "KPM control returned an empty response\n");
        return 1;
    }
    return 0;
}

static int command_ping(const char *key)
{
    char response[CONTROL_BUFFER_SIZE];
    if (control(key, "ping", response, sizeof(response)) != 0) return 1;
    if (strncmp(response, "pong ", 5) != 0) {
        fprintf(stderr, "unexpected ping response: %s\n", response);
        return 1;
    }
    printf("syscall-roundtrip %s\n", response);
    return 0;
}

static bool mapping_contains(uintptr_t address, char *matched, size_t matched_size)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];

    if (!maps) return false;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0;
        unsigned long end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 && address >= start && address < end) {
            snprintf(matched, matched_size, "%s", line);
            matched[strcspn(matched, "\r\n")] = '\0';
            fclose(maps);
            return true;
        }
    }
    fclose(maps);
    return false;
}

static int command_alloc(const char *key)
{
    char response[CONTROL_BUFFER_SIZE];
    char map_line[512] = { 0 };
    unsigned long address_value = 0;
    unsigned long size = 0;
    long pid = -1;
    volatile unsigned char *memory;

    if (control(key, "alloc", response, sizeof(response)) != 0) return 1;
    if (sscanf(response, "ok address=0x%lx size=%lu pid=%ld", &address_value, &size, &pid) != 3) {
        fprintf(stderr, "unexpected allocation response: %s\n", response);
        return 1;
    }
    if (size != STAGE0_PAGE_SIZE || pid != (long)getpid()) {
        fprintf(stderr,
                "allocation metadata mismatch: address=0x%lx size=%lu kernel-pid=%ld user-pid=%ld\n",
                address_value,
                size,
                pid,
                (long)getpid());
        return 1;
    }

    memory = (volatile unsigned char *)(uintptr_t)address_value;
    for (size_t index = 0; index < size; ++index) memory[index] = (unsigned char)(index ^ 0xA5U);
    for (size_t index = 0; index < size; ++index) {
        if (memory[index] != (unsigned char)(index ^ 0xA5U)) {
            fprintf(stderr, "memory verification failed at offset=%zu\n", index);
            munmap((void *)(uintptr_t)address_value, size);
            return 1;
        }
    }

    if (!mapping_contains((uintptr_t)address_value, map_line, sizeof(map_line))) {
        fprintf(stderr, "allocated address is absent from /proc/self/maps\n");
        munmap((void *)(uintptr_t)address_value, size);
        return 1;
    }

    if (munmap((void *)(uintptr_t)address_value, size) != 0) {
        fprintf(stderr, "munmap failed: %s\n", strerror(errno));
        return 1;
    }

    printf("anonymous-allocation verified address=0x%lx size=%lu pid=%ld\n", address_value, size, pid);
    printf("maps-visible %s\n", map_line);
    printf("anonymous-allocation unmapped=1\n");
    return 0;
}

static int command_list(const char *key)
{
    char names[1024] = { 0 };
    long result = rtgum_sc_kpm_list(key, names, sizeof(names));
    if (result < 0) return report_call_error("KPM list", result);
    printf("loaded-kpms count=%ld\n%s", rtgum_sc_kpm_nums(key), names);
    if (names[0] && names[strlen(names) - 1] != '\n') putchar('\n');
    return 0;
}

static int command_info(const char *key)
{
    char info[1024] = { 0 };
    long result = rtgum_sc_kpm_info(key, MODULE_NAME, info, sizeof(info));
    if (result < 0) return report_call_error("KPM info", result);
    printf("module-info %s\n", info);
    return 0;
}

static int command_unload(const char *key)
{
    long result = rtgum_sc_kpm_unload(key, MODULE_NAME);
    if (result != 0) return report_call_error("KPM unload", result);
    printf("unloaded module=%s\n", MODULE_NAME);
    return 0;
}

static int command_dmesg(const char *key)
{
    struct rtgum_su_profile profile = { 0 };
    long result;

    profile.uid = (uint32_t)getuid();
    profile.to_uid = 0;
    result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) {
        fprintf(stderr, "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }

    execl("/system/bin/dmesg", "dmesg", (char *)NULL);
    fprintf(stderr, "exec dmesg failed: %s\n", strerror(errno));
    return 1;
}

static int module_is_loaded(const char *key)
{
    char names[1024] = { 0 };
    const char *cursor = names;
    const size_t module_name_length = strlen(MODULE_NAME);
    long result = rtgum_sc_kpm_list(key, names, sizeof(names));

    if (result < 0) {
        report_call_error("KPM list", result);
        return -1;
    }
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length == module_name_length && !memcmp(cursor, MODULE_NAME, length)) return 1;
        if (!end) break;
        cursor = end + 1;
    }
    return 0;
}

static int command_smoke(const char *key, const char *path)
{
    int loaded;
    if (command_ready(key) != 0) return 1;

    loaded = module_is_loaded(key);
    if (loaded < 0) return 1;
    if (!loaded) {
        if (command_load(key, path) != 0) return 1;
    } else {
        printf("reuse-loaded module=%s\n", MODULE_NAME);
    }

    if (command_ping(key) != 0) return 1;
    if (command_alloc(key) != 0) return 1;
    puts("stage0-smoke PASS");
    return 0;
}

int main(int argc, char **argv)
{
    const char *key;
    const char *command;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    key = require_key();
    if (!key) return 2;
    command = argv[1];

    if (!strcmp(command, "ready")) return command_ready(key);
    if (!strcmp(command, "load") && argc == 3) return command_load(key, argv[2]);
    if (!strcmp(command, "ping")) return command_ping(key);
    if (!strcmp(command, "alloc")) return command_alloc(key);
    if (!strcmp(command, "list")) return command_list(key);
    if (!strcmp(command, "info")) return command_info(key);
    if (!strcmp(command, "dmesg")) return command_dmesg(key);
    if (!strcmp(command, "unload")) return command_unload(key);
    if (!strcmp(command, "smoke") && argc == 3) return command_smoke(key, argv[2]);

    usage(argv[0]);
    return 2;
}
