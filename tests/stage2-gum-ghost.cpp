/*
 * librtgum-gum-ghost.so: Frida Gum backend for the stage-2 Daemon.
 *
 * Loaded by the Daemon through the KPM's private linker (never via the
 * platform loader): no maps entry, no link_map presence. It links the Frida
 * Gum devkit (libfrida-gum.a) plus libc/libdl/libm; the KPM resolves every
 * import against the target app's already-loaded libraries.
 *
 * Interceptor trampoline allocations are routed to the KPM ghost allocator
 * by interposing mmap/munmap/mprotect inside this image: Gum's own code and
 * trampoline pages therefore stay VMA-less like the Daemon itself.
 *
 * Exports:
 *   ghostEntry(void*)        - dummy; the KPM's MODULE_LINK looks it up
 *   rtgum_gum_entry(host, out) - binds the host table, returns the Gum API
 */

#include <rtgum/gum_api.h>

#include <atomic>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <asm/hwcap.h>

#include <frida-gum.h>

#include "../tools/dbi/rtgum-dbi-follow.h"

/* The devkit's amalgamated public header intentionally omits the ARM64
 * relocator API even though its static archive exports it.  Multi-trace has
 * to account for the prologue that Interceptor moved to on_invoke_trampoline:
 * Stalker starts from the listener and therefore observes the relocated PC,
 * not the original function PC.  Keep this declaration byte-for-byte aligned
 * with Frida Gum 17.22.2's gumarm64relocator.h, which is the pinned devkit
 * linked by build-stage2-daemon.ps1. */
struct GumArm64Relocator {
    volatile gint ref_count;
    csh capstone;
    const guint8 *input_start;
    const guint8 *input_cur;
    GumAddress input_pc;
    cs_insn **input_insns;
    GumArm64Writer *output;
    guint inpos;
    guint outpos;
    gboolean eob;
    gboolean eoi;
    arm64_reg scratch_reg;
    GumMemoryRange code_range;
};

extern "C" void gum_arm64_relocator_init(GumArm64Relocator *,
                                           gconstpointer, GumArm64Writer *);
extern "C" void gum_arm64_relocator_clear(GumArm64Relocator *);
extern "C" guint gum_arm64_relocator_read_one(GumArm64Relocator *,
                                                const cs_insn **);
extern "C" cs_insn *gum_arm64_relocator_peek_next_write_insn(
    GumArm64Relocator *);
extern "C" void gum_arm64_relocator_skip_one(GumArm64Relocator *);
extern "C" gboolean gum_arm64_relocator_write_one(GumArm64Relocator *);
extern "C" arm64_reg gum_arm64_relocator_pick_exit_reg(
    GumArm64Relocator *, GumAddress);
extern "C" gpointer _gum_interceptor_translate_top_return_address(gpointer);

/* The devkit's gum_do_query_cpu_features() returns zero on Linux/Android
 * AArch64. On a PAC-enabled Pixel, Stalker then forwards a signed LR as a
 * raw instruction address to Capstone and faults during translation. Wrap
 * the query at link time so every devkit caller sees the kernel's PACA
 * capability and emits XPACI in its branch/return transfer paths. XPACI is
 * address normalization only; it does not authenticate the pointer. */
extern "C" GumCpuFeatures __real_gum_query_cpu_features(void);
extern "C" GumCpuFeatures __wrap_gum_query_cpu_features(void)
{
    GumCpuFeatures features = __real_gum_query_cpu_features();
    if ((getauxval(AT_HWCAP) & HWCAP_PACA) != 0)
        features = static_cast<GumCpuFeatures>(features | GUM_CPU_PTRAUTH);
    return features;
}

namespace {

/* Do not retain caller-owned table storage. Gum's deferred worker activity can
 * outlive a Daemon teardown transition; dereferencing a borrowed table in a
 * VMA-less Daemon page used to fault inside mmap(). */
RtGumHost g_host_storage{};
const RtGumHost *g_host = nullptr;
bool g_ghost_memory_enabled = false;
GumInterceptor *g_interceptor = nullptr;
bool g_initialized = false;

/* Size-aware ownership for mmap interposition.  The KPM may represent one
 * logical allocation as several 512 KiB Mapping records; munmap therefore
 * has to return the complete span instead of freeing only its first chunk. */
struct GhostAllocation {
    unsigned long address;
    unsigned long requested_size;
    unsigned long span_size;
    unsigned int protection;
    bool active;
};

constexpr unsigned int kMaximumGhostAllocations = 256U;
GhostAllocation g_ghost_allocations[kMaximumGhostAllocations]{};
std::atomic_flag g_ghost_allocations_lock = ATOMIC_FLAG_INIT;

void ghost_allocations_lock()
{
    while (g_ghost_allocations_lock.test_and_set(std::memory_order_acquire))
        asm volatile("yield" ::: "memory");
}

void ghost_allocations_unlock()
{
    g_ghost_allocations_lock.clear(std::memory_order_release);
}

bool remember_ghost_allocation(unsigned long address,
                               unsigned long requested_size,
                               unsigned long span_size,
                               unsigned int protection)
{
    bool remembered = false;
    ghost_allocations_lock();
    for (GhostAllocation &allocation : g_ghost_allocations) {
        if (allocation.active) continue;
        allocation.address = address;
        allocation.requested_size = requested_size;
        allocation.span_size = span_size;
        allocation.protection = protection;
        allocation.active = true;
        remembered = true;
        break;
    }
    ghost_allocations_unlock();
    return remembered;
}

void update_ghost_allocation_protection(unsigned long address,
                                        unsigned int protection)
{
    ghost_allocations_lock();
    for (GhostAllocation &allocation : g_ghost_allocations) {
        if (!allocation.active || allocation.address != address) continue;
        allocation.protection = protection;
        break;
    }
    ghost_allocations_unlock();
}

bool find_ghost_allocation(unsigned long address,
                           bool containing,
                           GhostAllocation &result)
{
    bool found = false;
    ghost_allocations_lock();
    for (const GhostAllocation &allocation : g_ghost_allocations) {
        if (!allocation.active) continue;
        const bool match = containing
            ? address >= allocation.address &&
                  address - allocation.address < allocation.span_size
            : address == allocation.address;
        if (!match) continue;
        result = allocation;
        found = true;
        break;
    }
    ghost_allocations_unlock();
    return found;
}

bool forget_ghost_allocation(unsigned long address, GhostAllocation &result)
{
    bool found = false;
    ghost_allocations_lock();
    for (GhostAllocation &allocation : g_ghost_allocations) {
        if (!allocation.active || allocation.address != address) continue;
        result = allocation;
        allocation = {};
        found = true;
        break;
    }
    ghost_allocations_unlock();
    return found;
}

long allocate_ghost_span(unsigned long size,
                         unsigned int protection,
                         unsigned long *out_address)
{
    if (!g_host || !out_address || size == 0UL) return -22;
    *out_address = 0UL;
    unsigned long address = 0UL;
    unsigned long span_size = 0UL;
    long status = -95;
    if (g_host->ghost_alloc_span != nullptr) {
        status = g_host->ghost_alloc_span(size, protection, &address, &span_size);
    } else if (g_host->ghost_alloc != nullptr) {
        status = g_host->ghost_alloc(size, protection, &address);
        span_size = (size + 0xfffUL) & ~0xfffUL;
    }
    if (status != 0 || address == 0UL || span_size == 0UL)
        return status != 0 ? status : -12;
    if (!remember_ghost_allocation(address, size, span_size, protection)) {
        if (g_host->ghost_free_span != nullptr)
            (void)g_host->ghost_free_span(address, span_size);
        else if (g_host->ghost_free != nullptr)
            (void)g_host->ghost_free(address);
        return -12;
    }
    *out_address = address;
    return 0;
}

long allocate_ghost_span_near(unsigned long size,
                              unsigned long alignment,
                              unsigned int protection,
                              unsigned long near_address,
                              unsigned long max_distance,
                              unsigned long *out_address)
{
    if (!g_host || !g_host->ghost_alloc_near_span || !out_address ||
        size == 0UL || near_address == 0UL || max_distance < size)
        return -22;
    *out_address = 0UL;
    unsigned long address = 0UL;
    unsigned long span_size = 0UL;
    const long status = g_host->ghost_alloc_near_span(
        size, alignment, protection, near_address, max_distance,
        &address, &span_size);
    if (status != 0 || address == 0UL || span_size == 0UL)
        return status != 0 ? status : -12;
    if (!remember_ghost_allocation(address, size, span_size, protection)) {
        if (g_host->ghost_free_span != nullptr)
            (void)g_host->ghost_free_span(address, span_size);
        else if (g_host->ghost_free != nullptr)
            (void)g_host->ghost_free(address);
        return -12;
    }
    *out_address = address;
    return 0;
}

long release_ghost_span(unsigned long address, unsigned long supplied_size)
{
    GhostAllocation allocation{};
    if (!find_ghost_allocation(address, false, allocation)) return -2;
    const unsigned long supplied_span = (supplied_size + 0xfffUL) & ~0xfffUL;
    if (supplied_size != 0UL && supplied_span != allocation.span_size) return -22;
    if (!forget_ghost_allocation(address, allocation)) return -16;
    const long status = g_host && g_host->ghost_free_span
        ? g_host->ghost_free_span(allocation.address, allocation.span_size)
        : g_host && g_host->ghost_free
              ? g_host->ghost_free(allocation.address)
              : -95;
    if (status != 0)
        (void)remember_ghost_allocation(allocation.address,
                                        allocation.requested_size,
                                        allocation.span_size,
                                        allocation.protection);
    return status;
}

void ghost_log(const char *text);

struct PltWatch;

struct TrampolineAlias {
    unsigned long trampoline_pc;
    unsigned long original_pc;
    uint32_t instruction;
};

constexpr unsigned int kMaximumTrampolineAliases = 128U;

struct StalkerScope {
    GumStalker *stalker = nullptr;
    GumStalkerTransformer *transformer = nullptr;
    GumEventSink *sink = nullptr;
    RtGumStalkerStats *stats = nullptr;
    unsigned long watched_start = 0;
    unsigned long watched_end = 0;
    unsigned long stack_low = 0;
    unsigned long stack_high = 0;
    unsigned int trace_mode = RTGUM_TRACE_MODE_EXECUTED_PATH |
                              RTGUM_TRACE_MODE_SUMMARY;
    unsigned int mem_read_mode = RTGUM_TRACE_MEM_READ_CODE;
    bool supports_bti = false;
    GumModuleRegistry *module_registry = nullptr;
    gulong module_added_handler = 0;
    PltWatch *plt_watch = nullptr;
    TrampolineAlias aliases[kMaximumTrampolineAliases]{};
    unsigned int alias_count = 0U;
    struct ReturnFrame {
        unsigned long expected;
        unsigned long stack_pointer;
        int depth;
    };
    ReturnFrame returns[256]{};
    unsigned int return_count = 0;
};

/* Gum follows at most one execution stream on a given thread.  Keep the
 * active scope as a pointer so an asynchronous trace invocation can own its
 * complete state instead of borrowing one process-global configuration. */
thread_local StalkerScope *g_current_stalker_scope = nullptr;
thread_local StalkerScope g_legacy_stalker_scope;

struct StalkerCalloutData {
    StalkerScope *scope;
    unsigned long spec;
};

struct GtraceCalloutData {
    StalkerScope *scope;
    unsigned long pc;
    uint32_t instruction;
};

unsigned long normalize_code_address(unsigned long address)
{
#if defined(__aarch64__)
    /* XPACI only removes address signatures. The transformer must perform
     * hardware authentication before Gum uses this normalized address. */
    __asm__ volatile(".arch_extension pauth\n\txpaci %0" : "+r"(address));
#endif
    return address;
}

/* GumInvocationContext lives inside GumInvocationStackEntry.  These two
 * prefixes expose only the stable fields needed to recover the active
 * GumFunctionContext and its relocated prologue.  Runtime checks below must
 * all pass before any trampoline address is trusted. */
struct InterceptorFramePrefix {
    void *function_context;
    void *caller_return_address;
    void *stack_address;
    GumAddress stack_id;
    GumInvocationContext invocation_context;
};

struct FunctionContextLayout1722 {
    void *function_address;
    void *grafted_hook;
    void *import_target;
    guint8 type;
    guint8 destroyed;
    guint8 activated;
    guint8 has_on_leave_listener;
    guint8 has_unignorable_listener;
    guint8 padding0[3];
    void *trampoline_slice;
    void *trampoline_deflector;
    gint trampoline_usage_counter;
    guint8 padding1[4];
    void *on_enter_trampoline;
    guint8 *overwritten_prologue;
    guint overwritten_prologue_len;
    guint8 padding2[4];
    guint8 *redirect_code;
    void *on_invoke_trampoline;
    void *on_leave_trampoline;
    void *listener_entries;
    void *replacement_function;
    void *replacement_data;
    gint scratch_register;
    gint scenario;
    gint relocation_policy;
    guint8 padding3[4];
    void *write_redirect;
    void *write_redirect_data;
    guint redirect_space_hint;
    guint8 padding4[4];
    guint8 backend_data[4U * sizeof(void *)];
    void *interceptor;
};

static_assert(offsetof(InterceptorFramePrefix, invocation_context) == 32U,
              "unexpected Gum invocation-frame layout");
static_assert(offsetof(FunctionContextLayout1722, on_invoke_trampoline) == 88U,
              "unexpected Gum function-context trampoline layout");
static_assert(offsetof(FunctionContextLayout1722, backend_data) == 168U,
              "unexpected Gum function-context backend layout");

long build_trampoline_aliases(GumInvocationContext *context,
                              unsigned long target,
                              TrampolineAlias *aliases,
                              unsigned int *alias_count)
{
    if (context == nullptr || aliases == nullptr || alias_count == nullptr)
        return -22;
    *alias_count = 0U;
    auto *frame = reinterpret_cast<InterceptorFramePrefix *>(
        reinterpret_cast<guint8 *>(context) -
        offsetof(InterceptorFramePrefix, invocation_context));
    auto *function = static_cast<FunctionContextLayout1722 *>(
        frame->function_context);
    if (function == nullptr ||
        normalize_code_address(reinterpret_cast<unsigned long>(
            function->function_address)) != target ||
        normalize_code_address(reinterpret_cast<unsigned long>(
            context->function)) != target ||
        function->overwritten_prologue == nullptr ||
        function->on_invoke_trampoline == nullptr ||
        function->overwritten_prologue_len == 0U ||
        (function->overwritten_prologue_len & 3U) != 0U ||
        function->overwritten_prologue_len / 4U >
            kMaximumTrampolineAliases)
        return -95;

    guint redirect_size = 0U;
    arm64_reg scratch_reg = ARM64_REG_INVALID;
    memcpy(&redirect_size, function->backend_data, sizeof(redirect_size));
    memcpy(&scratch_reg, function->backend_data + sizeof(guint),
           sizeof(scratch_reg));
    if ((redirect_size != 4U && redirect_size != 8U &&
         redirect_size != 16U) ||
        scratch_reg == ARM64_REG_INVALID)
        return -95;

    const unsigned long invoke = normalize_code_address(
        reinterpret_cast<unsigned long>(function->on_invoke_trampoline));
    if (invoke == 0UL) return -95;

    alignas(16) guint8 generated[4096]{};
    GumArm64Writer writer{};
    GumArm64Relocator relocator{};
    gum_arm64_writer_init(&writer, generated);
    writer.pc = static_cast<GumAddress>(invoke);
    gum_arm64_relocator_init(&relocator, function->overwritten_prologue,
                             &writer);
    /* Bytes come from Gum's pristine copy, while Capstone PCs must describe
     * the original function so ADR/ADRP/branches are rewritten identically. */
    relocator.input_pc = static_cast<GumAddress>(target);
    relocator.scratch_reg = scratch_reg;

    guint read = 0U;
    while (read < function->overwritten_prologue_len) {
        const cs_insn *instruction = nullptr;
        read = gum_arm64_relocator_read_one(&relocator, &instruction);
        if (read == 0U || read > function->overwritten_prologue_len ||
            instruction == nullptr)
            break;
    }
    if (read != function->overwritten_prologue_len) {
        gum_arm64_relocator_clear(&relocator);
        writer.flush_on_destroy = FALSE;
        gum_arm64_writer_clear(&writer);
        return -95;
    }

    const bool rewrite_lr =
        (relocator.inpos == 2U &&
         strcmp(relocator.input_insns[0]->mnemonic, "mov") == 0 &&
         strcmp(relocator.input_insns[1]->mnemonic, "b") == 0) ||
        (relocator.inpos >= 4U &&
         strcmp(relocator.input_insns[0]->mnemonic, "stp") == 0 &&
         strcmp(relocator.input_insns[1]->mnemonic, "mov") == 0 &&
         strcmp(relocator.input_insns[2]->mnemonic, "mov") == 0 &&
         strcmp(relocator.input_insns[3]->mnemonic, "bl") == 0);

    long result = 0;
    while (result == 0) {
        cs_insn *instruction =
            gum_arm64_relocator_peek_next_write_insn(&relocator);
        if (instruction == nullptr) break;
        const guint output_offset = gum_arm64_writer_offset(&writer);
        if (output_offset >= sizeof(generated) - 512U ||
            *alias_count == kMaximumTrampolineAliases) {
            result = -7;
            break;
        }
        TrampolineAlias &alias = aliases[(*alias_count)++];
        alias.trampoline_pc = invoke + output_offset;
        alias.original_pc = static_cast<unsigned long>(instruction->address);
        alias.instruction = static_cast<uint32_t>(instruction->bytes[0]) |
            (static_cast<uint32_t>(instruction->bytes[1]) << 8U) |
            (static_cast<uint32_t>(instruction->bytes[2]) << 16U) |
            (static_cast<uint32_t>(instruction->bytes[3]) << 24U);

        const cs_arm64 &details = instruction->detail->arm64;
        const bool reads_lr = rewrite_lr && instruction->id == ARM64_INS_MOV &&
            details.op_count >= 2U &&
            details.operands[1].type == ARM64_OP_REG &&
            details.operands[1].reg == ARM64_REG_LR;
        if (!reads_lr) {
            if (!gum_arm64_relocator_write_one(&relocator)) result = -95;
            continue;
        }

        const arm64_reg destination = details.operands[0].reg;
        guint destination_index = 0U;
        if (destination >= ARM64_REG_X0 && destination <= ARM64_REG_X28)
            destination_index = destination - ARM64_REG_X0;
        else if (destination >= ARM64_REG_X29 &&
                 destination <= ARM64_REG_X30)
            destination_index = destination - ARM64_REG_X29;
        else {
            result = -95;
            break;
        }
        gum_arm64_writer_put_push_all_x_registers(&writer);
        gum_arm64_writer_put_call_address_with_arguments(
            &writer,
            GUM_ADDRESS(_gum_interceptor_translate_top_return_address), 1,
            GUM_ARG_REGISTER, ARM64_REG_LR);
        const guint slot = (destination_index * sizeof(void *)) /
                           (2U * sizeof(void *));
        guint frame_offset = (15U - slot) * 2U * sizeof(void *);
        if ((destination_index & 1U) != 0U) frame_offset += sizeof(void *);
        if (!gum_arm64_writer_put_str_reg_reg_offset(
                &writer, ARM64_REG_X0, ARM64_REG_SP, frame_offset)) {
            result = -95;
            break;
        }
        gum_arm64_writer_put_pop_all_x_registers(&writer);
        gum_arm64_relocator_skip_one(&relocator);
    }

    if (result == 0 && !relocator.eoi) {
        const GumAddress resume = target + function->overwritten_prologue_len;
        arm64_reg exit_reg = gum_arm64_relocator_pick_exit_reg(&relocator,
                                                                resume);
        if (exit_reg == ARM64_REG_INVALID) exit_reg = scratch_reg;
        if (!gum_arm64_writer_put_ldr_reg_address(
                &writer, exit_reg, gum_sign_code_address(resume)) ||
            !gum_arm64_writer_put_jmp_reg(&writer, exit_reg))
            result = -95;
    }
    if (result == 0 && !gum_arm64_writer_flush(&writer)) result = -95;
    const guint generated_size = gum_arm64_writer_offset(&writer);
    if (result == 0 &&
        (generated_size == 0U || generated_size > sizeof(generated) ||
         memcmp(reinterpret_cast<const void *>(invoke), generated,
                generated_size) != 0))
        result = -74;

    gum_arm64_relocator_clear(&relocator);
    writer.flush_on_destroy = FALSE;
    gum_arm64_writer_clear(&writer);
    if (result != 0) *alias_count = 0U;
    return result;
}

unsigned long cpu_register(const GumCpuContext *cpu, unsigned int reg)
{
    if (reg < 29U) return cpu->x[reg];
    if (reg == 29U) return cpu->fp;
    if (reg == 30U) return cpu->lr;
    if (reg == 32U) return cpu->sp;
    return 0;
}

bool condition_holds(unsigned int condition, unsigned long nzcv)
{
    const bool n = ((nzcv >> 31U) & 1UL) != 0UL;
    const bool z = ((nzcv >> 30U) & 1UL) != 0UL;
    const bool c = ((nzcv >> 29U) & 1UL) != 0UL;
    const bool v = ((nzcv >> 28U) & 1UL) != 0UL;
    bool result = false;
    switch ((condition >> 1U) & 7U) {
        case 0U: result = z; break;               /* EQ / NE */
        case 1U: result = c; break;               /* CS / CC */
        case 2U: result = n; break;               /* MI / PL */
        case 3U: result = v; break;               /* VS / VC */
        case 4U: result = c && !z; break;         /* HI / LS */
        case 5U: result = n == v; break;          /* GE / LT */
        case 6U: result = !z && n == v; break;    /* GT / LE */
        case 7U: result = true; break;             /* AL / NV */
    }
    if ((condition & 1U) != 0U && condition != 15U) result = !result;
    return result;
}

long long sign_extend_field(unsigned long value, unsigned int bits)
{
    const unsigned long sign = 1UL << (bits - 1U);
    return static_cast<long long>((value ^ sign) - sign);
}

unsigned long gtrace_next_pc(const GtraceCalloutData &data,
                             const GumCpuContext *cpu)
{
    const uint32_t word = data.instruction;
    const unsigned long fallthrough = data.pc + 4UL;
    if (!cpu) return fallthrough;
    if ((word & 0x7C000000U) == 0x14000000U) {
        const long long delta = sign_extend_field(word & 0x03FFFFFFU, 26U) * 4LL;
        return static_cast<unsigned long>(static_cast<long long>(data.pc) + delta);
    }
    if ((word & 0xFF000010U) == 0x54000000U) {
        if (!condition_holds(word & 0xFU, cpu->nzcv)) return fallthrough;
        const long long delta = sign_extend_field((word >> 5U) & 0x7FFFFU, 19U) * 4LL;
        return static_cast<unsigned long>(static_cast<long long>(data.pc) + delta);
    }
    if ((word & 0x7E000000U) == 0x34000000U) {
        unsigned long value = cpu_register(cpu, word & 31U);
        if ((word & 0x80000000U) == 0U) value &= 0xFFFFFFFFUL;
        const bool nonzero = (word & (1U << 24U)) != 0U;
        const bool take = nonzero ? value != 0UL : value == 0UL;
        if (!take) return fallthrough;
        const long long delta = sign_extend_field((word >> 5U) & 0x7FFFFU, 19U) * 4LL;
        return static_cast<unsigned long>(static_cast<long long>(data.pc) + delta);
    }
    if ((word & 0x7E000000U) == 0x36000000U) {
        const unsigned int bit = ((word >> 31U) & 1U) << 5U |
                                 ((word >> 19U) & 31U);
        const bool set = ((cpu_register(cpu, word & 31U) >> bit) & 1UL) != 0UL;
        const bool branch_if_set = (word & (1U << 24U)) != 0U;
        if (set != branch_if_set) return fallthrough;
        const long long delta = sign_extend_field((word >> 5U) & 0x3FFFU, 14U) * 4LL;
        return static_cast<unsigned long>(static_cast<long long>(data.pc) + delta);
    }
    const uint32_t register_branch = word & 0xFFFFFC1FU;
    if (register_branch == 0xD61F0000U ||
        register_branch == 0xD63F0000U ||
        register_branch == 0xD65F0000U ||
        (word & 0xFEFFF800U) == 0xD61F0800U ||
        (word & 0xFEFFF800U) == 0xD63F0800U) {
        return normalize_code_address(cpu_register(cpu, (word >> 5U) & 31U));
    }
    if (word == 0xD65F0BFFU || word == 0xD65F0FFFU)
        return normalize_code_address(cpu->lr);
    return fallthrough;
}

void stalker_gtrace_record(GumCpuContext *cpu, gpointer user)
{
    const auto *callout = static_cast<const GtraceCalloutData *>(user);
    if (!callout || !callout->scope || !callout->scope->stats) return;
    RtGumStalkerStats *stats = callout->scope->stats;
    if (!stats->gtrace_buffer || stats->gtrace_capacity == 0UL) return;
    RtGumGtraceStep step{};
    step.sequence = ++stats->gtrace_total;
    step.pc = callout->pc;
    step.next_pc = gtrace_next_pc(*callout, cpu);
    if (callout->scope->mem_read_mode == RTGUM_TRACE_MEM_READ_CODE) {
        step.instruction = callout->instruction;
        step.flags |= RTGUM_GTRACE_STEP_INSN_VALID;
    }
    step.flags |= RTGUM_GTRACE_STEP_NEXT_VALID |
                 RTGUM_GTRACE_STEP_DYNAMIC |
                 RTGUM_GTRACE_STEP_DBI_CALLOUT;
    unsigned long slot = 0UL;
    if (stats->gtrace_count < stats->gtrace_capacity) {
        slot = (stats->gtrace_head + stats->gtrace_count) % stats->gtrace_capacity;
        ++stats->gtrace_count;
    } else {
        slot = stats->gtrace_head;
        stats->gtrace_head = (stats->gtrace_head + 1UL) % stats->gtrace_capacity;
        ++stats->gtrace_dropped;
    }
    stats->gtrace_buffer[slot] = step;
}

void rotate_gtrace_ring(RtGumStalkerStats *stats)
{
    if (!stats || !stats->gtrace_buffer || stats->gtrace_count == 0UL ||
        stats->gtrace_head == 0UL)
        return;
    auto reverse = [&](unsigned long begin, unsigned long end) {
        while (begin < end) {
            --end;
            if (begin >= end) break;
            const RtGumGtraceStep temporary = stats->gtrace_buffer[begin];
            stats->gtrace_buffer[begin] = stats->gtrace_buffer[end];
            stats->gtrace_buffer[end] = temporary;
            ++begin;
        }
    };
    /* A non-zero head only occurs for a full ring. Three reversals rotate the
     * oldest entry to slot zero without an allocation in the ghost backend. */
    reverse(0UL, stats->gtrace_head);
    reverse(stats->gtrace_head, stats->gtrace_count);
    reverse(0UL, stats->gtrace_count);
    stats->gtrace_head = 0UL;
}

struct PltExclusionState {
    GumStalker *stalker;
    GArray *seen;
    GArray *guarded;
    GumAddress module_start;
    GumAddress module_end;
    unsigned int ranges;
};

struct PltWatch {
    GArray *seen;
    GArray *guarded;
    GArray *veneers;
    gint pending;
    gint active;
};

struct PltVeneerRange {
    GumMemoryRange plt;
    unsigned long base;
    unsigned long mapped_size;
};

enum class BtiGuard : int {
    Unknown = -1,
    Unguarded = 0,
    Guarded = 1,
};

struct BtiMapEntry {
    unsigned long begin;
    unsigned long end;
    BtiGuard guard;
};

/* Reading /proc/self/smaps for every PLT and every indirect branch made the
 * first trace hit take tens of seconds on real applications.  Cache one
 * process-wide snapshot instead.  The fixed array keeps lookups safe from a
 * Stalker callout (no allocator, stdio, or dynamic container involved). */
constexpr unsigned int kMaximumBtiMapEntries = 4096U;
BtiMapEntry g_bti_maps[kMaximumBtiMapEntries]{};
unsigned int g_bti_map_count = 0U;
bool g_bti_map_valid = false;
bool g_bti_map_complete = false;
pthread_rwlock_t g_bti_map_lock = PTHREAD_RWLOCK_INITIALIZER;
std::atomic<unsigned int> g_bti_map_dirty{1U};

BtiGuard bti_guard_for_address(unsigned long address);

gboolean exclude_plt_section(const GumSectionDetails *details, gpointer user)
{
    auto *state = static_cast<PltExclusionState *>(user);
    if (details->size == 0 || details->name == nullptr) return TRUE;
    const char *name = details->name;
    if (strcmp(name, ".plt") != 0 && strcmp(name, ".plt.got") != 0 &&
        strcmp(name, ".plt.sec") != 0 && strcmp(name, ".iplt") != 0)
        return TRUE;
    if (details->address < state->module_start ||
        details->address >= state->module_end ||
        details->size > state->module_end - details->address)
        return TRUE;
    GumMemoryRange range{};
    range.base_address = details->address;
    range.size = details->size;
    for (guint i = 0; i < state->seen->len; ++i) {
        const auto &prior = g_array_index(state->seen, GumMemoryRange, i);
        if (prior.base_address == range.base_address &&
            prior.size == range.size)
            return TRUE;
    }
    /* Gum's excluded-call transfer uses BR. BTI-c PLT entries need a
     * call-class transfer; record them for the transformer instead. */
    const BtiGuard guard = bti_guard_for_address(details->address);
    if (guard == BtiGuard::Guarded) {
        for (guint i = 0; i < state->guarded->len; ++i) {
            const auto &prior = g_array_index(state->guarded, GumMemoryRange, i);
            if (prior.base_address == range.base_address &&
                prior.size == range.size)
                return TRUE;
        }
        g_array_append_val(state->guarded, range);
        return TRUE;
    }
    if (guard != BtiGuard::Unguarded)
        return TRUE;
    g_array_append_val(state->seen, range);
    gum_stalker_exclude(state->stalker, &range);
    ++state->ranges;
    return TRUE;
}

gboolean exclude_module_plt(GumModule *module, gpointer user)
{
    auto *state = static_cast<PltExclusionState *>(user);
    const GumMemoryRange *module_range = gum_module_get_range(module);
    if (module_range == nullptr || module_range->size == 0) return TRUE;
    state->module_start = module_range->base_address;
    if (module_range->size > ~GumAddress{0} - state->module_start)
        return TRUE;
    state->module_end = state->module_start + module_range->size;
    gum_module_enumerate_sections(module, exclude_plt_section, state);
    return TRUE;
}

void destroy_plt_watch(gpointer user, GClosure *)
{
    auto *watch = static_cast<PltWatch *>(user);
    if (watch->veneers != nullptr) {
        for (guint i = 0; i < watch->veneers->len; ++i) {
            const auto &entry = g_array_index(watch->veneers, PltVeneerRange, i);
            register long x0 __asm__("x0") = static_cast<long>(entry.base);
            register long x1 __asm__("x1") = static_cast<long>(entry.mapped_size);
            register long x8 __asm__("x8") = 215; /* arm64 munmap */
            __asm__ volatile("svc #0" : "+r"(x0)
                             : "r"(x1), "r"(x8) : "memory", "cc");
        }
        g_array_free(watch->veneers, TRUE);
    }
    g_array_free(watch->seen, TRUE);
    g_array_free(watch->guarded, TRUE);
    g_free(watch);
}

void on_module_added(GumModuleRegistry *, GumModule *, gpointer user)
{
    auto *watch = static_cast<PltWatch *>(user);
    if (!g_atomic_int_get(&watch->active)) return;
    /* Loader notifications may run while Gum holds the registry lock. Defer
     * section enumeration and Stalker mutation to its owner transformer. */
    g_atomic_int_set(&watch->pending, 1);
    g_bti_map_dirty.store(1U, std::memory_order_release);
}

void disconnect_plt_watch(StalkerScope *scope)
{
    if (scope->module_registry == nullptr) return;
    if (scope->plt_watch != nullptr) {
        g_atomic_int_set(&scope->plt_watch->active, 0);
        scope->plt_watch = nullptr;
    }
    if (scope->module_added_handler != 0)
        g_signal_handler_disconnect(scope->module_registry,
                                    scope->module_added_handler);
    g_object_unref(scope->module_registry);
    scope->module_registry = nullptr;
    scope->module_added_handler = 0;
}

BtiGuard bti_guard_for_address(unsigned long address)
{
    /* This runs from a Gum callout. Keep the VmFlags snapshot free of stdio
     * and heap allocation so it cannot re-enter the translated loader path. */
    auto raw_syscall3 = [](long number, long arg0, long arg1, long arg2) -> long {
        register long x0 __asm__("x0") = arg0;
        register long x1 __asm__("x1") = arg1;
        register long x2 __asm__("x2") = arg2;
        register long x8 __asm__("x8") = number;
        __asm__ volatile("svc #0" : "+r"(x0)
                         : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
        return x0;
    };
    constexpr long kOpenat = 56;
    constexpr long kClose = 57;
    constexpr long kRead = 63;
    auto hex_digit = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };

    if (g_bti_map_dirty.load(std::memory_order_acquire) != 0U) {
        pthread_rwlock_wrlock(&g_bti_map_lock);
        if (g_bti_map_dirty.load(std::memory_order_relaxed) != 0U) {
            g_bti_map_count = 0U;
            g_bti_map_valid = false;
            g_bti_map_complete = true;
            const long fd = raw_syscall3(kOpenat, AT_FDCWD,
                reinterpret_cast<long>("/proc/self/smaps"),
                O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                char block[4096];
                char line[512];
                unsigned int line_size = 0U;
                bool line_overflow = false;
                unsigned long pending_begin = 0UL;
                unsigned long pending_end = 0UL;
                bool pending = false;
                bool read_ok = true;
                auto consume_line = [&](unsigned int length, bool overflow) {
                    unsigned int cursor = 0U;
                    unsigned long begin = 0UL;
                    while (cursor < length) {
                        const int digit = hex_digit(line[cursor]);
                        if (digit < 0 || begin > (~0UL >> 4U)) break;
                        begin = (begin << 4U) |
                            static_cast<unsigned long>(digit);
                        ++cursor;
                    }
                    if (cursor != 0U && cursor < length &&
                        line[cursor] == '-') {
                        ++cursor;
                        const unsigned int first = cursor;
                        unsigned long end = 0UL;
                        while (cursor < length) {
                            const int digit = hex_digit(line[cursor]);
                            if (digit < 0 || end > (~0UL >> 4U)) break;
                            end = (end << 4U) |
                                static_cast<unsigned long>(digit);
                            ++cursor;
                        }
                        pending = cursor > first && end > begin;
                        pending_begin = begin;
                        pending_end = end;
                        return;
                    }
                    if (!pending || overflow || length < 8U ||
                        line[0] != 'V' || line[1] != 'm' ||
                        line[2] != 'F' || line[3] != 'l' ||
                        line[4] != 'a' || line[5] != 'g' ||
                        line[6] != 's' || line[7] != ':')
                        return;
                    bool guarded = false;
                    for (unsigned int at = 8U; at + 1U < length; ++at) {
                        if (line[at] == 'b' && line[at + 1U] == 't' &&
                            (at == 8U || line[at - 1U] == ' ' ||
                             line[at - 1U] == '\t') &&
                            (at + 2U == length || line[at + 2U] == ' ' ||
                             line[at + 2U] == '\t')) {
                            guarded = true;
                            break;
                        }
                    }
                    if (g_bti_map_count == kMaximumBtiMapEntries) {
                        g_bti_map_complete = false;
                    } else {
                        g_bti_maps[g_bti_map_count++] = BtiMapEntry{
                            pending_begin, pending_end,
                            guarded ? BtiGuard::Guarded
                                    : BtiGuard::Unguarded};
                    }
                    pending = false;
                };
                for (;;) {
                    const long count = raw_syscall3(kRead, fd,
                        reinterpret_cast<long>(block), sizeof(block));
                    if (count < 0) {
                        read_ok = false;
                        break;
                    }
                    if (count == 0) break;
                    for (long index = 0; index < count; ++index) {
                        const char value = block[index];
                        if (value != '\n') {
                            if (line_size + 1U < sizeof(line))
                                line[line_size++] = value;
                            else
                                line_overflow = true;
                            continue;
                        }
                        consume_line(line_size, line_overflow);
                        line_size = 0U;
                        line_overflow = false;
                    }
                }
                if (line_size != 0U)
                    consume_line(line_size, line_overflow);
                raw_syscall3(kClose, fd, 0, 0);
                g_bti_map_valid = read_ok;
            }
            g_bti_map_dirty.store(0U, std::memory_order_release);
        }
        pthread_rwlock_unlock(&g_bti_map_lock);
    }

    BtiGuard result = BtiGuard::Unknown;
    pthread_rwlock_rdlock(&g_bti_map_lock);
    if (g_bti_map_valid) {
        result = g_bti_map_complete ? BtiGuard::Unguarded
                                    : BtiGuard::Unknown;
        for (unsigned int index = 0U; index < g_bti_map_count; ++index) {
            const BtiMapEntry &entry = g_bti_maps[index];
            if (entry.begin <= address && address < entry.end) {
                result = entry.guard;
                break;
            }
        }
    }
    pthread_rwlock_unlock(&g_bti_map_lock);
    /* A VMA-less ghost page cannot carry VM_ARM64_BTI. An incomplete smaps
     * snapshot is different: fail closed instead of assuming unguarded. */
    return result;
}

long raw_memory_syscall(long number, long arg0, long arg1, long arg2,
                        long arg3, long arg4, long arg5)
{
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x4 __asm__("x4") = arg4;
    register long x5 __asm__("x5") = arg5;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8) : "memory", "cc");
    return x0;
}

unsigned long guarded_plt_veneer(PltWatch *watch,
                                 const GumMemoryRange &range,
                                 unsigned long target)
{
    if (target < range.base_address ||
        target - range.base_address >= range.size ||
        ((target - range.base_address) & 3UL) != 0 ||
        range.size > (1UL << 20U))
        return 0;
    for (guint i = 0; i < watch->veneers->len; ++i) {
        const auto &entry = g_array_index(watch->veneers, PltVeneerRange, i);
        if (entry.plt.base_address == range.base_address &&
            entry.plt.size == range.size)
            return entry.base + (target - range.base_address) * 2UL;
    }
    const unsigned long bytes = ((range.size + 3UL) / 4UL) * 8UL;
    const unsigned long length = (bytes + 4095UL) & ~4095UL;
    const unsigned long center = range.base_address & ~4095UL;
    constexpr long kMapFixedNoReplace = 0x100000;
    constexpr long kProtBti = 0x10;
    for (unsigned int i = 1; i <= 1920; ++i) {
        const unsigned long distance = static_cast<unsigned long>(i) * 65536UL;
        const unsigned long candidates[2] = {
            center <= ~0UL - distance ? center + distance : 0,
            center >= distance ? center - distance : 0,
        };
        for (unsigned int side = 0; side < 2; ++side) {
            const unsigned long candidate = candidates[side];
            if (candidate == 0) continue;
            const long mapped = raw_memory_syscall(222, /* arm64 mmap */
                static_cast<long>(candidate), static_cast<long>(length),
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | kMapFixedNoReplace,
                -1, 0);
            if (mapped != static_cast<long>(candidate)) {
                if (mapped >= 0)
                    raw_memory_syscall(215, mapped,
                        static_cast<long>(length), 0, 0, 0, 0);
                continue;
            }
            auto *words = reinterpret_cast<uint32_t *>(candidate);
            bool reachable = true;
            const unsigned long slots = (range.size + 3UL) / 4UL;
            for (unsigned long slot = 0; slot < slots; ++slot) {
                const unsigned long destination =
                    range.base_address + slot * 4UL;
                const unsigned long branch = candidate + slot * 8UL + 4UL;
                const int64_t delta = static_cast<int64_t>(destination) -
                                      static_cast<int64_t>(branch);
                if ((delta & 3L) != 0 ||
                    delta < -(1LL << 27U) || delta >= (1LL << 27U)) {
                    reachable = false;
                    break;
                }
                words[slot * 2UL] = 0xd503245fU; /* BTI c */
                words[slot * 2UL + 1UL] = 0x14000000U |
                    (static_cast<uint32_t>(delta / 4L) & 0x03ffffffU);
            }
            if (reachable) {
                __builtin___clear_cache(reinterpret_cast<char *>(candidate),
                    reinterpret_cast<char *>(candidate + bytes));
                reachable = raw_memory_syscall(226, /* arm64 mprotect */
                    static_cast<long>(candidate), static_cast<long>(length),
                    PROT_READ | PROT_EXEC | kProtBti, 0, 0, 0) == 0;
            }
            if (!reachable) {
                raw_memory_syscall(215, static_cast<long>(candidate),
                    static_cast<long>(length), 0, 0, 0, 0);
                continue;
            }
            PltVeneerRange entry{range, candidate, length};
            g_array_append_val(watch->veneers, entry);
            return candidate + (target - range.base_address) * 2UL;
        }
    }
    return 0;
}

void stalker_pac_check(GumCpuContext *cpu, gpointer user)
{
    const auto *callout = static_cast<const StalkerCalloutData *>(user);
    StalkerScope *scope = callout->scope;
    RtGumStalkerStats *stats = scope->stats;
    const unsigned long spec = callout->spec;
    const unsigned int target_reg = static_cast<unsigned int>(spec & 63UL);
    const unsigned int modifier_reg = static_cast<unsigned int>((spec >> 6U) & 63UL);
    const bool key_b = (spec & (1UL << 12U)) != 0;
    const bool pac = (spec & (1UL << 13U)) != 0;
    const bool links = (spec & (1UL << 14U)) != 0;
    const bool check_bti = (spec & (1UL << 15U)) != 0;
    const unsigned long signed_target = cpu_register(cpu, target_reg);
    if (pac) {
        const unsigned long modifier = cpu_register(cpu, modifier_reg);
        unsigned long authenticated = signed_target;
        if (key_b) {
            __asm__ volatile(".arch_extension pauth\n\tautib %0, %1"
                             : "+r"(authenticated) : "r"(modifier) : "memory");
        } else {
            __asm__ volatile(".arch_extension pauth\n\tautia %0, %1"
                             : "+r"(authenticated) : "r"(modifier) : "memory");
        }
        /* FPAC traps during AUTI. Older CPUs poison the pointer instead;
         * never let Gum's subsequent XPACI erase that failure. */
        if (authenticated != normalize_code_address(signed_target))
            __builtin_trap();
        if (stats != nullptr) ++stats->pac_checks;
    }
    if (!check_bti || !scope->supports_bti) return;
    if (stats != nullptr) ++stats->bti_checks;
    const unsigned long target = normalize_code_address(signed_target);
    const BtiGuard guard = bti_guard_for_address(target);
    if (guard == BtiGuard::Unknown) __builtin_trap();
    if (guard != BtiGuard::Guarded) return;
    if (stats != nullptr) ++stats->bti_guarded;
    rtgum_dbi::LandingEvidence evidence{};
    evidence.guard_known = true;
    evidence.guarded = true;
    evidence.authenticated = pac;
    evidence.links = links;
    evidence.first_instruction =
        *reinterpret_cast<const volatile unsigned int *>(target);
    const rtgum_dbi::BranchClass kind = pac
        ? rtgum_dbi::BranchClass::Pac
        : links ? rtgum_dbi::BranchClass::Call
                : rtgum_dbi::BranchClass::Branch;
    if (rtgum_dbi::validate_landing(kind, &evidence) ==
        rtgum_dbi::FollowStatus::Ok)
        return;
    if (stats != nullptr) ++stats->bti_rejected;
    /* The software check rejected this guarded landing. Execute the same
     * kind of hardware indirect branch only on this failure path so the
     * device reports its native BTI exception and no code is bypassed. */
    if (links)
        __asm__ volatile("blr %0" :: "r"(target) : "x30", "memory");
    else
        __asm__ volatile("br %0" :: "r"(target) : "memory");
    __builtin_trap();
}

void stalker_transform(GumStalkerIterator *iterator,
                       GumStalkerOutput *output, gpointer user)
{
    auto *scope = static_cast<StalkerScope *>(user);
    if (scope->plt_watch != nullptr &&
        g_atomic_int_exchange(&scope->plt_watch->pending, 0) != 0) {
        PltExclusionState state{scope->stalker, scope->plt_watch->seen,
                                scope->plt_watch->guarded,
                                0, 0, 0};
        gum_process_enumerate_modules(exclude_module_plt, &state);
    }
    const cs_insn *insn = nullptr;
    while (gum_stalker_iterator_next(iterator, &insn)) {
        const unsigned int id = insn->id;
        const uint32_t native_word = static_cast<uint32_t>(insn->bytes[0]) |
            (static_cast<uint32_t>(insn->bytes[1]) << 8U) |
            (static_cast<uint32_t>(insn->bytes[2]) << 16U) |
            (static_cast<uint32_t>(insn->bytes[3]) << 24U);
        const TrampolineAlias *alias = nullptr;
        for (unsigned int index = 0U; index != scope->alias_count; ++index) {
            if (scope->aliases[index].trampoline_pc == insn->address) {
                alias = &scope->aliases[index];
                break;
            }
        }
        const unsigned long trace_pc = alias != nullptr
            ? alias->original_pc
            : static_cast<unsigned long>(insn->address);
        const uint32_t trace_word = alias != nullptr
            ? alias->instruction
            : native_word;
        if ((scope->trace_mode & RTGUM_TRACE_MODE_EXECUTED_PATH) != 0U &&
            scope->stats != nullptr && scope->stats->gtrace_buffer != nullptr &&
            scope->stats->gtrace_capacity != 0UL &&
            trace_pc >= scope->watched_start &&
            trace_pc < scope->watched_end) {
            auto *gtrace = static_cast<GtraceCalloutData *>(
                g_malloc(sizeof(GtraceCalloutData)));
            if (gtrace != nullptr) {
                gtrace->scope = scope;
                gtrace->pc = trace_pc;
                gtrace->instruction = trace_word;
                gum_stalker_iterator_put_callout(iterator, stalker_gtrace_record,
                                                 gtrace, g_free);
            }
        }
        bool native_guarded_plt_call = false;
        if (id == ARM64_INS_BL && scope->plt_watch != nullptr &&
            scope->plt_watch->guarded != nullptr && output != nullptr &&
            output->writer.arm64 != nullptr) {
            if ((native_word & 0xfc000000U) == 0x94000000U) {
                const int64_t displacement =
                    static_cast<int64_t>(
                        static_cast<int32_t>((native_word & 0x03ffffffU) << 6U) >> 6U)
                    * 4L;
                const unsigned long target = static_cast<unsigned long>(
                    static_cast<int64_t>(insn->address) + displacement);
                bool section_matched = false;
                for (guint i = 0; i < scope->plt_watch->guarded->len; ++i) {
                    const auto &range = g_array_index(scope->plt_watch->guarded,
                                                      GumMemoryRange, i);
                    if (target < range.base_address ||
                        target - range.base_address >= range.size)
                        continue;
                    section_matched = true;
                    /* The real PLT entry may lack a BTI landing despite its
                     * VMA being guarded. BLR enters a BTI-c veneer; its direct
                     * B to PLT retains the original BL's landing semantics. */
                    const unsigned long veneer = guarded_plt_veneer(
                        scope->plt_watch, range, target);
                    if (veneer != 0) {
                        gum_arm64_writer_put_ldr_reg_address(
                            output->writer.arm64, ARM64_REG_X16, veneer);
                        gum_arm64_writer_put_blr_reg_no_auth(
                            output->writer.arm64, ARM64_REG_X16);
                        native_guarded_plt_call = true;
                    }
                    break;
                }
                if (!section_matched &&
                    bti_guard_for_address(target) == BtiGuard::Guarded) {
                    const auto *entry = reinterpret_cast<
                        const volatile uint32_t *>(target);
                    const uint32_t a = entry[0], b = entry[1];
                    const uint32_t c = entry[2], d = entry[3];
                    if ((a & 0x9f00001fU) == 0x90000010U &&
                        (b & 0xffc003ffU) == 0xf9400211U &&
                        (c & 0xffc003ffU) == 0x91000210U &&
                        d == 0xd61f0220U) {
                        const GumMemoryRange one_entry{target, 4UL};
                        const unsigned long veneer = guarded_plt_veneer(
                            scope->plt_watch, one_entry, target);
                        if (veneer != 0) {
                            gum_arm64_writer_put_ldr_reg_address(
                                output->writer.arm64, ARM64_REG_X16, veneer);
                            gum_arm64_writer_put_blr_reg_no_auth(
                                output->writer.arm64, ARM64_REG_X16);
                            native_guarded_plt_call = true;
                        }
                    }
                }
            }
        }
        if (native_guarded_plt_call) continue;
        const bool pac_branch = id == ARM64_INS_BRAA ||
                                id == ARM64_INS_BRAAZ ||
                                id == ARM64_INS_BRAB ||
                                id == ARM64_INS_BRABZ ||
                                id == ARM64_INS_BLRAA ||
                                id == ARM64_INS_BLRAAZ ||
                                id == ARM64_INS_BLRAB ||
                                id == ARM64_INS_BLRABZ;
        const bool pac_return = id == ARM64_INS_RETAA || id == ARM64_INS_RETAB;
        const bool ordinary_branch = id == ARM64_INS_BR ||
                                     id == ARM64_INS_BLR;
        if (pac_branch || pac_return || ordinary_branch) {
            unsigned int target_reg = 30U;
            unsigned int modifier_reg = 32U; /* SP for RETAA/RETAB */
            if (pac_branch || ordinary_branch) {
                target_reg = (native_word >> 5U) & 31U;
                modifier_reg = native_word & 31U; /* XZR denotes zero modifier */
            }
            const bool key_b = id == ARM64_INS_BRAB ||
                               id == ARM64_INS_BRABZ ||
                               id == ARM64_INS_BLRAB ||
                               id == ARM64_INS_BLRABZ ||
                               id == ARM64_INS_RETAB;
            const bool links = id == ARM64_INS_BLR ||
                               id == ARM64_INS_BLRAA ||
                               id == ARM64_INS_BLRAAZ ||
                               id == ARM64_INS_BLRAB ||
                               id == ARM64_INS_BLRABZ;
            const unsigned long spec = target_reg |
                (static_cast<unsigned long>(modifier_reg) << 6U) |
                (key_b ? (1UL << 12U) : 0UL) |
                ((pac_branch || pac_return) ? (1UL << 13U) : 0UL) |
                (links ? (1UL << 14U) : 0UL) |
                ((pac_branch || ordinary_branch) ? (1UL << 15U) : 0UL);
            auto *callout = static_cast<StalkerCalloutData *>(
                g_malloc(sizeof(StalkerCalloutData)));
            callout->scope = scope;
            callout->spec = spec;
            gum_stalker_iterator_put_callout(iterator, stalker_pac_check,
                callout, g_free);
        }
        gum_stalker_iterator_keep(iterator);
    }
}

void stalker_event(const GumEvent *event, GumCpuContext *cpu, gpointer user)
{
    auto *scope = static_cast<StalkerScope *>(user);
    auto *stats = scope->stats;
    if (stats == nullptr) return;
    switch (event->type) {
        case GUM_BLOCK: ++stats->blocks; break;
        case GUM_CALL: {
            ++stats->calls;
            const unsigned long call_site = reinterpret_cast<unsigned long>(
                event->call.location);
            /* A resumed catch/longjmp can bypass the RET event entirely.
             * Before recording the next call, drop frames whose
             * caller stack has already been restored. ABI-conforming nested
             * calls normally have a lower SP; equal SP indicates a sibling
             * call after a non-local transfer in the tested fixtures. Only
             * compare SPs on the original thread
             * stack, so an alternate signal stack cannot retire live frames.
             * Keep unmatched frames visible at stop. */
            if (cpu != nullptr && scope->stack_low != 0 &&
                cpu->sp >= scope->stack_low && cpu->sp < scope->stack_high) {
                while (scope->return_count != 0 &&
                       scope->returns[scope->return_count - 1].stack_pointer != 0 &&
                       cpu->sp >= scope->returns[scope->return_count - 1].stack_pointer) {
                    --scope->return_count;
                    ++stats->unwound_frames;
                }
            }
            if (call_site < scope->watched_start ||
                call_site >= scope->watched_end)
                break;
            if (scope->return_count == sizeof(scope->returns) /
                                       sizeof(scope->returns[0])) {
                ++stats->shadow_overflow;
                break;
            }
            auto &frame = scope->returns[scope->return_count++];
            frame.expected = call_site + 4UL;
            frame.stack_pointer = cpu != nullptr ? cpu->sp : 0;
            frame.depth = event->call.depth;
            break;
        }
        case GUM_RET: {
            ++stats->returns;
            const int depth = event->ret.depth - 1;
            /* Returns from deeper, unwatched callees do not belong to a
             * watched call frame. A lower depth can indicate a signal or
             * non-local transfer; report the discontinuity, not success. */
            if (scope->return_count == 0 ||
                depth > scope->returns[scope->return_count - 1].depth)
                break;
            while (scope->return_count != 0 &&
                   scope->returns[scope->return_count - 1].depth > depth) {
                --scope->return_count;
                ++stats->unwound_frames;
            }
            if (scope->return_count == 0 ||
                scope->returns[scope->return_count - 1].depth != depth) {
                ++stats->unpaired_returns;
                break;
            }
            const auto frame = scope->returns[--scope->return_count];
            const unsigned long expected = frame.expected;
            const unsigned long actual = normalize_code_address(
                reinterpret_cast<unsigned long>(event->ret.target));
            if (expected == actual)
                ++stats->matched_returns;
            else {
                ++stats->mismatched_returns;
                if (stats->mismatch_samples_used < 4) {
                    auto &sample = stats->mismatch_samples[
                        stats->mismatch_samples_used++];
                    sample.call_offset = static_cast<unsigned short>(
                        (expected - 4UL) & 0xfffUL);
                    sample.ret_offset = static_cast<unsigned short>(
                        reinterpret_cast<unsigned long>(
                            event->ret.location) & 0xfffUL);
                    sample.expected_offset = static_cast<unsigned short>(
                        expected & 0xfffUL);
                    sample.actual_offset = static_cast<unsigned short>(
                        actual & 0xfffUL);
                    sample.call_depth = frame.depth;
                    sample.ret_depth = event->ret.depth;
                }
            }
            break;
        }
        case GUM_COMPILE: ++stats->compiled; break;
        default: break;
    }
}

long gum_stalker_start_scope(StalkerScope *scope,
                             RtGumStalkerStats *stats,
                             unsigned long watched_start,
                             unsigned long watched_size,
                             unsigned int trace_mode,
                             unsigned int mem_read_mode,
                             const TrampolineAlias *aliases,
                             unsigned int alias_count)
{
    constexpr unsigned int kTraceModes = RTGUM_TRACE_MODE_EXECUTED_PATH |
                                         RTGUM_TRACE_MODE_SUMMARY;
    if (!g_initialized || scope == nullptr || stats == nullptr ||
        watched_start == 0 || watched_size == 0 ||
        watched_size > (1UL << 20) ||
        ((watched_start | watched_size) & 3UL) != 0 ||
        watched_start > ~0UL - watched_size || trace_mode == 0U ||
        (trace_mode & ~kTraceModes) != 0U ||
        mem_read_mode > RTGUM_TRACE_MEM_READ_CODE ||
        ((stats->gtrace_buffer == nullptr) != (stats->gtrace_capacity == 0UL)) ||
        stats->gtrace_capacity > 4096UL ||
        alias_count > kMaximumTrampolineAliases ||
        ((aliases == nullptr) != (alias_count == 0U)) ||
        (((trace_mode & RTGUM_TRACE_MODE_EXECUTED_PATH) != 0U) !=
         (stats->gtrace_capacity != 0UL)))
        return -22;
    if (g_current_stalker_scope != nullptr || scope->stalker != nullptr)
        return -16;
    if (!gum_stalker_is_supported()) return -95;
    RtGumGtraceStep *const gtrace_buffer = stats->gtrace_buffer;
    const unsigned long gtrace_capacity = stats->gtrace_capacity;
    *stats = RtGumStalkerStats{};
    stats->gtrace_buffer = gtrace_buffer;
    stats->gtrace_capacity = gtrace_capacity;
    *scope = StalkerScope{};
    scope->stats = stats;
    scope->watched_start = watched_start;
    scope->watched_end = watched_start + watched_size;
    scope->trace_mode = trace_mode;
    scope->mem_read_mode = mem_read_mode;
    if (alias_count != 0U) {
        memcpy(scope->aliases, aliases,
               alias_count * sizeof(TrampolineAlias));
        scope->alias_count = alias_count;
    }
    GumStalker *stalker = gum_stalker_new();
    if (stalker == nullptr) return -12;
    GumStalkerTransformer *transformer =
        gum_stalker_transformer_make_from_callback(stalker_transform,
                                                   scope, nullptr);
    if (transformer == nullptr) {
        g_object_unref(stalker);
        *scope = StalkerScope{};
        return -12;
    }
    GumEventSink *sink = gum_event_sink_make_from_callback(
        GUM_BLOCK | GUM_CALL | GUM_RET | GUM_COMPILE,
        stalker_event, scope, nullptr);
    if (sink == nullptr) {
        g_object_unref(transformer);
        g_object_unref(stalker);
        *scope = StalkerScope{};
        return -12;
    }
    scope->stalker = stalker;
    scope->transformer = transformer;
    scope->sink = sink;
    /* A PLT in a module loaded after follow_me needs exclusion before its
     * first caller block is compiled. Loader notifications only flag a
     * refresh; the owner transformer performs enumeration and mutation. */
    /* obtain() returns a borrowed singleton. Hold our own reference until
     * disconnect_plt_watch(), including across repeated start/stop cycles. */
    GumModuleRegistry *const registry = gum_module_registry_obtain();
    scope->module_registry = registry == nullptr
        ? nullptr
        : static_cast<GumModuleRegistry *>(g_object_ref(registry));
    if (scope->module_registry == nullptr) {
        *scope = StalkerScope{};
        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);
        return -12;
    }
    auto *watch = static_cast<PltWatch *>(g_malloc0(sizeof(PltWatch)));
    if (watch == nullptr) {
        disconnect_plt_watch(scope);
        *scope = StalkerScope{};
        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);
        return -12;
    }
    watch->seen = g_array_new(FALSE, FALSE, sizeof(GumMemoryRange));
    watch->guarded = g_array_new(FALSE, FALSE, sizeof(GumMemoryRange));
    watch->veneers = g_array_new(FALSE, FALSE, sizeof(PltVeneerRange));
    if (watch->seen == nullptr || watch->guarded == nullptr ||
        watch->veneers == nullptr) {
        if (watch->seen != nullptr) g_array_free(watch->seen, TRUE);
        if (watch->guarded != nullptr) g_array_free(watch->guarded, TRUE);
        if (watch->veneers != nullptr) g_array_free(watch->veneers, TRUE);
        g_free(watch);
        disconnect_plt_watch(scope);
        *scope = StalkerScope{};
        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);
        return -12;
    }
    g_atomic_int_set(&watch->active, 1);
    scope->plt_watch = watch;
    scope->module_added_handler = g_signal_connect_data(
        scope->module_registry, "module-added",
        G_CALLBACK(on_module_added), watch, destroy_plt_watch,
        static_cast<GConnectFlags>(0));
    if (scope->module_added_handler == 0) {
        g_array_free(watch->seen, TRUE);
        g_array_free(watch->guarded, TRUE);
        g_array_free(watch->veneers, TRUE);
        g_free(watch);
        scope->plt_watch = nullptr;
        disconnect_plt_watch(scope);
        *scope = StalkerScope{};
        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);
        return -12;
    }
    /* Android's PLT tail-branches through X17. Keep known unguarded PLTs
     * native to preserve the loader callback across the call/return handoff. */
    PltExclusionState plt_exclusion{stalker, watch->seen,
                                    watch->guarded, 0, 0, 0};
    gum_module_registry_enumerate_modules(scope->module_registry,
                                          exclude_module_plt, &plt_exclusion);
    if (plt_exclusion.ranges == 0 && watch->guarded->len == 0) {
        disconnect_plt_watch(scope);
        *scope = StalkerScope{};
        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);
        return -95;
    }
    pthread_attr_t thread_attributes;
    if (pthread_getattr_np(pthread_self(), &thread_attributes) == 0) {
        void *stack_base = nullptr;
        size_t stack_size = 0;
        if (pthread_attr_getstack(&thread_attributes, &stack_base,
                                  &stack_size) == 0 &&
            stack_size <= ~0UL - reinterpret_cast<unsigned long>(stack_base)) {
            scope->stack_low =
                reinterpret_cast<unsigned long>(stack_base);
            scope->stack_high = scope->stack_low + stack_size;
        }
        pthread_attr_destroy(&thread_attributes);
    }
    scope->supports_bti = (getauxval(AT_HWCAP2) & HWCAP2_BTI) != 0;
    /* The synchronous callback uses this thread-local scope, which must be
     * initialized before follow_me translates its first block. */
    g_current_stalker_scope = scope;
    gum_stalker_follow_me(stalker, transformer, sink);
    return 0;
}

long gum_stalker_start_current(RtGumStalkerStats *stats,
                               unsigned long watched_start,
                               unsigned long watched_size)
{
    const unsigned int mode = RTGUM_TRACE_MODE_SUMMARY |
        ((stats != nullptr && stats->gtrace_buffer != nullptr)
             ? RTGUM_TRACE_MODE_EXECUTED_PATH : 0U);
    return gum_stalker_start_scope(&g_legacy_stalker_scope, stats,
                                   watched_start, watched_size, mode,
                                   RTGUM_TRACE_MEM_READ_CODE, nullptr, 0U);
}

long gum_stalker_invalidate_current(unsigned long address)
{
    if (address == 0 || g_current_stalker_scope != &g_legacy_stalker_scope ||
        g_legacy_stalker_scope.stalker == nullptr)
        return -22;
    gum_stalker_invalidate(g_legacy_stalker_scope.stalker,
                           reinterpret_cast<const void *>(address));
    return 0;
}

long gum_stalker_stop_scope(StalkerScope *scope)
{
    if (scope == nullptr || scope->stalker == nullptr) return -2;
    if (g_current_stalker_scope != scope) return -16;
    GumStalker *const stalker = scope->stalker;
    GumStalkerTransformer *const transformer = scope->transformer;
    GumEventSink *const sink = scope->sink;
    RtGumStalkerStats *const stats = scope->stats;
    gum_stalker_unfollow_me(stalker);
    gum_stalker_flush(stalker);
    gum_stalker_stop(stalker);
    disconnect_plt_watch(scope);
    if (stats != nullptr) {
        stats->shadow_remaining = scope->return_count;
        rotate_gtrace_ring(stats);
    }
    *scope = StalkerScope{};
    g_current_stalker_scope = nullptr;
    g_object_unref(sink);
    g_object_unref(transformer);
    g_object_unref(stalker);
    return 0;
}

long gum_stalker_stop_current()
{
    if (g_current_stalker_scope != &g_legacy_stalker_scope) return -2;
    return gum_stalker_stop_scope(&g_legacy_stalker_scope);
}

/* Real libc mmap family: our interposed versions fall back to them for
 * non-ghost operations (file mappings, fixed addresses, PROT_NONE). */
using MmapFn = void *(*)(void *, size_t, int, int, int, off_t);
using MunmapFn = int (*)(void *, size_t);
using MprotectFn = int (*)(void *, size_t, int);

std::atomic<MmapFn> real_mmap{nullptr};
std::atomic<MunmapFn> real_munmap{nullptr};
std::atomic<MprotectFn> real_mprotect{nullptr};
/* 0 = not attempted, 1 = resolving, 2 = complete.  A reentrant mmap made
 * by dlsym while state is 1 takes the raw-syscall fallback below. */
std::atomic<unsigned int> real_memory_state{0U};

void resolve_real_memory_functions()
{
    if (real_memory_state.load(std::memory_order_acquire) == 2U) return;
    unsigned int expected = 0U;
    if (!real_memory_state.compare_exchange_strong(
            expected, 1U, std::memory_order_acq_rel))
        return;

    auto mmap_candidate = reinterpret_cast<MmapFn>(dlsym(RTLD_NEXT, "mmap"));
    auto munmap_candidate =
        reinterpret_cast<MunmapFn>(dlsym(RTLD_NEXT, "munmap"));
    auto mprotect_candidate =
        reinterpret_cast<MprotectFn>(dlsym(RTLD_NEXT, "mprotect"));
    /* RTLD_DEFAULT may resolve these names back to this interposer depending
     * on the Android linker group ordering.  RTLD_NEXT should not, but keep
     * an explicit guard so a loader quirk can never turn fallback into
     * unbounded recursion. */
    if (mmap_candidate == &::mmap) mmap_candidate = nullptr;
    if (munmap_candidate == &::munmap) munmap_candidate = nullptr;
    if (mprotect_candidate == &::mprotect) mprotect_candidate = nullptr;
    real_mmap.store(mmap_candidate, std::memory_order_release);
    real_munmap.store(munmap_candidate, std::memory_order_release);
    real_mprotect.store(mprotect_candidate, std::memory_order_release);
    real_memory_state.store(2U, std::memory_order_release);
}

void ghost_log(const char *text)
{
    if (!g_host || !g_host->log) return;
    g_host->log(text);
}

enum : unsigned int {
    kTraceFree = 0U,
    kTracePreparing = 1U,
    kTraceActive = 2U,
    kTraceRetiring = 3U,
    kTraceReleasing = 4U,
};

struct TraceRegistration final {
    std::atomic<unsigned int> state{0U};
    std::atomic<unsigned long> invocations{0UL};
    std::atomic<unsigned long> completed{0UL};
    std::atomic<unsigned long> busy{0UL};
    std::atomic<unsigned long> failures{0UL};
    std::atomic<unsigned long> writer_errors{0UL};
    std::atomic<unsigned long> active{0UL};
    std::atomic<unsigned long> pins{0UL};
    std::atomic<unsigned long> handle{0UL};
    RtGumTraceConfig config{};
    GumInvocationListener *listener = nullptr;
};

struct TraceRun final {
    StalkerScope scope{};
    RtGumStalkerStats stats{};
};

struct TraceInvocationData final {
    TraceRegistration *registration;
    TraceRun *run;
    unsigned long invocation;
    long result;
    bool pinned;
};

constexpr unsigned int kMaximumTraceRegistrations = 16U;
TraceRegistration g_trace_registrations[kMaximumTraceRegistrations];
std::atomic<unsigned long> g_trace_generation{1UL};

TraceRegistration *trace_registration_for_handle(unsigned long handle)
{
    const unsigned long encoded = handle & 0xffUL;
    if (encoded == 0UL || encoded > kMaximumTraceRegistrations) return nullptr;
    TraceRegistration &registration = g_trace_registrations[encoded - 1UL];
    const unsigned int state = registration.state.load(std::memory_order_acquire);
    if ((state != kTraceActive && state != kTraceRetiring) ||
        registration.handle.load(std::memory_order_acquire) != handle)
        return nullptr;
    return &registration;
}

TraceRegistration *trace_pin_registration(unsigned long handle)
{
    TraceRegistration *registration = trace_registration_for_handle(handle);
    if (registration == nullptr) return nullptr;
    registration->pins.fetch_add(1UL, std::memory_order_acq_rel);
    const unsigned int state = registration->state.load(std::memory_order_acquire);
    if ((state == kTraceActive || state == kTraceRetiring) &&
        registration->handle.load(std::memory_order_acquire) == handle)
        return registration;
    registration->pins.fetch_sub(1UL, std::memory_order_acq_rel);
    return nullptr;
}

bool trace_config_valid(const RtGumTraceConfig *config)
{
    constexpr unsigned int kTraceModes = RTGUM_TRACE_MODE_EXECUTED_PATH |
                                         RTGUM_TRACE_MODE_SUMMARY;
    if (config == nullptr || config->version != RTGUM_TRACE_CONFIG_VERSION ||
        config->size < sizeof(RtGumTraceConfig) || config->target == 0UL ||
        config->watched_start == 0UL || config->watched_size == 0UL ||
        config->watched_size > (1UL << 20) ||
        ((config->target | config->watched_start | config->watched_size) & 3UL) != 0UL ||
        config->watched_start > ~0UL - config->watched_size ||
        config->target < config->watched_start ||
        config->target >= config->watched_start + config->watched_size ||
        config->trace_mode == 0U ||
        (config->trace_mode & ~kTraceModes) != 0U ||
        config->mem_read_mode > RTGUM_TRACE_MEM_READ_CODE ||
        config->writer == nullptr)
        return false;
    const bool path = (config->trace_mode &
                       RTGUM_TRACE_MODE_EXECUTED_PATH) != 0U;
    if (path)
        return config->step_capacity != 0UL &&
               config->step_capacity <= 4096UL;
    return config->step_capacity == 0UL;
}

void trace_listener_on_enter(GumInvocationContext *context, gpointer user)
{
    auto *registration = static_cast<TraceRegistration *>(user);
    auto *data = static_cast<TraceInvocationData *>(
        gum_invocation_context_get_listener_invocation_data(
            context, sizeof(TraceInvocationData)));
    if (data == nullptr || registration == nullptr) return;
    *data = TraceInvocationData{};
    data->registration = registration;
    registration->active.fetch_add(1UL, std::memory_order_acq_rel);
    if (registration->state.load(std::memory_order_acquire) != kTraceActive) {
        registration->active.fetch_sub(1UL, std::memory_order_acq_rel);
        return;
    }
    data->pinned = true;
    data->invocation = registration->invocations.fetch_add(
        1UL, std::memory_order_acq_rel) + 1UL;

    const unsigned long capacity =
        (registration->config.trace_mode & RTGUM_TRACE_MODE_EXECUTED_PATH) != 0U
            ? registration->config.step_capacity : 0UL;
    if (capacity > (~static_cast<unsigned long>(0) - sizeof(TraceRun)) /
                       sizeof(RtGumGtraceStep)) {
        data->result = -12;
        return;
    }
    const size_t allocation = sizeof(TraceRun) +
        static_cast<size_t>(capacity) * sizeof(RtGumGtraceStep);
    auto *run = static_cast<TraceRun *>(malloc(allocation));
    if (run == nullptr) {
        data->result = -12;
        return;
    }
    memset(run, 0, allocation);
    data->run = run;
    if (capacity != 0UL) {
        run->stats.gtrace_buffer = reinterpret_cast<RtGumGtraceStep *>(run + 1);
        run->stats.gtrace_capacity = capacity;
    }
    TrampolineAlias aliases[kMaximumTrampolineAliases]{};
    unsigned int alias_count = 0U;
    if (capacity != 0UL) {
        data->result = build_trampoline_aliases(
            context, registration->config.target, aliases, &alias_count);
        if (data->result != 0) {
            ghost_log(data->result == -74
                ? "rtgum-gum: interceptor trampoline layout mismatch"
                : "rtgum-gum: interceptor trampoline layout unsupported");
            return;
        }
    }
    data->result = gum_stalker_start_scope(
        &run->scope, &run->stats, registration->config.watched_start,
        registration->config.watched_size, registration->config.trace_mode,
        registration->config.mem_read_mode,
        alias_count == 0U ? nullptr : aliases, alias_count);
    if (data->result == -16)
        registration->busy.fetch_add(1UL, std::memory_order_relaxed);
}

void trace_listener_on_leave(GumInvocationContext *context, gpointer)
{
    auto *data = static_cast<TraceInvocationData *>(
        gum_invocation_context_get_listener_invocation_data(
            context, sizeof(TraceInvocationData)));
    if (data == nullptr || !data->pinned || data->registration == nullptr)
        return;
    TraceRegistration *const registration = data->registration;
    if (data->result == 0 && data->run != nullptr)
        data->result = gum_stalker_stop_scope(&data->run->scope);
    if (data->result == 0)
        registration->completed.fetch_add(1UL, std::memory_order_relaxed);
    else if (data->result != -16)
        registration->failures.fetch_add(1UL, std::memory_order_relaxed);

    RtGumTraceBatch batch{};
    batch.version = RTGUM_TRACE_BATCH_VERSION;
    batch.size = sizeof(batch);
    batch.handle = registration->handle.load(std::memory_order_acquire);
    batch.target = registration->config.target;
    batch.invocation = data->invocation;
    batch.thread_id = gum_invocation_context_get_thread_id(context);
    batch.trace_mode = registration->config.trace_mode;
    batch.mem_read_mode = registration->config.mem_read_mode;
    batch.result = data->result;
    if (data->run != nullptr) {
        const RtGumStalkerStats &stats = data->run->stats;
        batch.steps = stats.gtrace_buffer;
        batch.count = stats.gtrace_count;
        batch.total = stats.gtrace_total;
        batch.dropped = stats.gtrace_dropped;
        batch.blocks = stats.blocks;
        batch.calls = stats.calls;
        batch.returns = stats.returns;
        batch.compiled = stats.compiled;
    }
    const long written = registration->config.writer(
        &batch, registration->config.writer_user_data);
    if (written != 0)
        registration->writer_errors.fetch_add(1UL, std::memory_order_relaxed);
    free(data->run);
    data->run = nullptr;
    data->pinned = false;
    registration->active.fetch_sub(1UL, std::memory_order_acq_rel);
}

long gum_trace_start(const RtGumTraceConfig *config, unsigned long *out_handle)
{
    if (!g_initialized || !g_interceptor || out_handle == nullptr ||
        !trace_config_valid(config))
        return -22;
    *out_handle = 0UL;
    TraceRegistration *registration = nullptr;
    for (TraceRegistration &candidate : g_trace_registrations) {
        unsigned int expected = kTraceFree;
        if (candidate.state.compare_exchange_strong(
                expected, kTracePreparing, std::memory_order_acq_rel)) {
            registration = &candidate;
            break;
        }
    }
    if (registration == nullptr) return -12;

    unsigned long generation = g_trace_generation.fetch_add(
        1UL, std::memory_order_acq_rel);
    if (generation == 0UL)
        generation = g_trace_generation.fetch_add(1UL, std::memory_order_acq_rel);
    const unsigned long slot = static_cast<unsigned long>(
        registration - g_trace_registrations) + 1UL;
    registration->handle.store((generation << 8U) | slot,
                               std::memory_order_relaxed);
    registration->config = *config;
    registration->invocations.store(0UL, std::memory_order_relaxed);
    registration->completed.store(0UL, std::memory_order_relaxed);
    registration->busy.store(0UL, std::memory_order_relaxed);
    registration->failures.store(0UL, std::memory_order_relaxed);
    registration->writer_errors.store(0UL, std::memory_order_relaxed);
    registration->active.store(0UL, std::memory_order_relaxed);
    registration->pins.store(0UL, std::memory_order_relaxed);
    registration->listener = gum_make_call_listener(
        trace_listener_on_enter, trace_listener_on_leave, registration, nullptr);
    if (registration->listener == nullptr) {
        registration->config = RtGumTraceConfig{};
        registration->handle.store(0UL, std::memory_order_relaxed);
        registration->state.store(kTraceFree, std::memory_order_release);
        return -12;
    }
    registration->state.store(kTraceActive, std::memory_order_release);
    GumAttachOptions options{};
    options.ignorability = GUM_INVOCATION_UNIGNORABLE;
    const GumAttachReturn attached = gum_interceptor_attach(
        g_interceptor, reinterpret_cast<gpointer>(config->target),
        registration->listener, &options);
    if (attached != GUM_ATTACH_OK) {
        registration->state.store(kTraceRetiring, std::memory_order_release);
        g_object_unref(registration->listener);
        registration->listener = nullptr;
        registration->config = RtGumTraceConfig{};
        registration->handle.store(0UL, std::memory_order_relaxed);
        registration->state.store(kTraceFree, std::memory_order_release);
        return -22;
    }
    *out_handle = registration->handle.load(std::memory_order_acquire);
    return 0;
}

long gum_trace_stop(unsigned long handle)
{
    TraceRegistration *registration = trace_registration_for_handle(handle);
    if (registration == nullptr) return -2;
    unsigned int expected = kTraceActive;
    if (registration->state.compare_exchange_strong(
            expected, kTraceRetiring, std::memory_order_acq_rel)) {
        gum_interceptor_detach(g_interceptor, registration->listener);
    } else if (expected != kTraceRetiring) {
        return expected == kTraceReleasing ? -16 : -2;
    }
    if (registration->active.load(std::memory_order_acquire) != 0UL)
        return -16;

    expected = kTraceRetiring;
    if (!registration->state.compare_exchange_strong(
            expected, kTraceReleasing, std::memory_order_acq_rel))
        return expected == kTraceReleasing ? -16 : -2;
    for (unsigned int spin = 0U;
         registration->pins.load(std::memory_order_acquire) != 0UL &&
         spin != 10000U; ++spin)
        __asm__ volatile("yield" ::: "memory");
    if (registration->active.load(std::memory_order_acquire) != 0UL ||
        registration->pins.load(std::memory_order_acquire) != 0UL) {
        registration->state.store(kTraceRetiring, std::memory_order_release);
        return -16;
    }
    GumInvocationListener *const listener = registration->listener;
    registration->listener = nullptr;
    registration->config = RtGumTraceConfig{};
    registration->handle.store(0UL, std::memory_order_release);
    g_object_unref(listener);
    registration->state.store(kTraceFree, std::memory_order_release);
    return 0;
}

long gum_trace_query(unsigned long handle, RtGumTraceStats *out_stats)
{
    if (out_stats == nullptr) return -22;
    TraceRegistration *registration = trace_pin_registration(handle);
    if (registration == nullptr) return -2;
    RtGumTraceStats stats{};
    stats.version = RTGUM_TRACE_STATS_VERSION;
    stats.size = sizeof(stats);
    stats.handle = registration->handle.load(std::memory_order_acquire);
    stats.target = registration->config.target;
    stats.invocations = registration->invocations.load(std::memory_order_acquire);
    stats.completed = registration->completed.load(std::memory_order_acquire);
    stats.busy = registration->busy.load(std::memory_order_acquire);
    stats.failures = registration->failures.load(std::memory_order_acquire);
    stats.writer_errors = registration->writer_errors.load(
        std::memory_order_acquire);
    stats.active = registration->active.load(std::memory_order_acquire);
    stats.trace_mode = registration->config.trace_mode;
    stats.mem_read_mode = registration->config.mem_read_mode;
    stats.retiring = registration->state.load(std::memory_order_acquire) ==
                     kTraceRetiring ? 1U : 0U;
    *out_stats = stats;
    registration->pins.fetch_sub(1UL, std::memory_order_acq_rel);
    return 0;
}

struct Listener final {
    void (*on_enter)(RtGumInvocation *invocation, void *user_data);
    void (*on_leave)(RtGumInvocation *invocation, void *user_data);
    void *user_data;
    unsigned long function_address;
};

/* Frida's interceptor stores the listener by raw pointer without taking a
 * ref (gum_function_context_add_listener keeps listener_instance only), so
 * the caller's reference must outlive the attachment. Attach and replace
 * registrations share one slot table. Handles include a slot, kind, and
 * generation so a stale listener handle can never detach a later hook that
 * happened to reuse the same slot. */
enum HookSlotState : unsigned int {
    kHookSlotFree = 0U,
    kHookSlotPreparing = 1U,
    kHookSlotActive = 2U,
    kHookSlotRetiring = 3U,
};

enum HookSlotKind : unsigned int {
    kHookSlotListener = 1U,
    kHookSlotReplacement = 2U,
};

struct ListenerSlot final {
    GumInvocationListener *call_listener = nullptr;
    unsigned long target = 0UL;
    unsigned long handle = 0UL;
    HookSlotState state = kHookSlotFree;
    HookSlotKind kind = kHookSlotListener;
};

constexpr std::size_t kMaximumListenerSlots = 16U;
ListenerSlot g_listener_slots[kMaximumListenerSlots];
std::atomic_flag g_listener_slots_lock = ATOMIC_FLAG_INIT;
std::atomic<unsigned long> g_listener_generation{1UL};

constexpr unsigned int kHookHandleSlotBits = 8U;
constexpr unsigned int kHookHandleKindBits = 8U;
constexpr unsigned int kHookHandleKindShift = kHookHandleSlotBits;
constexpr unsigned int kHookHandleGenerationShift =
    kHookHandleSlotBits + kHookHandleKindBits;
constexpr unsigned long kHookHandleSlotMask =
    (1UL << kHookHandleSlotBits) - 1UL;
constexpr unsigned long kHookHandleKindMask =
    (1UL << kHookHandleKindBits) - 1UL;
constexpr unsigned long kHookHandleGenerationMask =
    ~0UL >> kHookHandleGenerationShift;

void listener_slots_lock()
{
    while (g_listener_slots_lock.test_and_set(std::memory_order_acquire))
        __asm__ volatile("yield" ::: "memory");
}

void listener_slots_unlock()
{
    g_listener_slots_lock.clear(std::memory_order_release);
}

unsigned long make_hook_handle(std::size_t slot, HookSlotKind kind)
{
    unsigned long generation = 0UL;
    while (generation == 0UL) {
        generation = g_listener_generation.fetch_add(
            1UL, std::memory_order_acq_rel) & kHookHandleGenerationMask;
    }
    return (generation << kHookHandleGenerationShift) |
           (static_cast<unsigned long>(kind) << kHookHandleKindShift) |
           (static_cast<unsigned long>(slot) + 1UL);
}

ListenerSlot *reserve_listener_slot(HookSlotKind kind,
                                    unsigned long *out_handle)
{
    ListenerSlot *slot = nullptr;
    listener_slots_lock();
    for (ListenerSlot &candidate : g_listener_slots) {
        if (candidate.state != kHookSlotFree) continue;
        slot = &candidate;
        const std::size_t index = static_cast<std::size_t>(
            slot - g_listener_slots);
        slot->call_listener = nullptr;
        slot->target = 0UL;
        slot->kind = kind;
        slot->handle = make_hook_handle(index, kind);
        slot->state = kHookSlotPreparing;
        *out_handle = slot->handle;
        break;
    }
    listener_slots_unlock();
    return slot;
}

void release_listener_slot_reservation(ListenerSlot *slot,
                                       unsigned long handle)
{
    listener_slots_lock();
    if (slot != nullptr && slot->state == kHookSlotPreparing &&
        slot->handle == handle)
        *slot = ListenerSlot{};
    listener_slots_unlock();
}

bool hook_handle_shape_valid(unsigned long handle,
                             std::size_t *out_slot,
                             HookSlotKind *out_kind)
{
    const unsigned long encoded_slot = handle & kHookHandleSlotMask;
    const unsigned long encoded_kind =
        (handle >> kHookHandleKindShift) & kHookHandleKindMask;
    const unsigned long generation = handle >> kHookHandleGenerationShift;
    if (encoded_slot == 0UL || encoded_slot > kMaximumListenerSlots ||
        generation == 0UL ||
        (encoded_kind != kHookSlotListener &&
         encoded_kind != kHookSlotReplacement))
        return false;
    *out_slot = static_cast<std::size_t>(encoded_slot - 1UL);
    *out_kind = static_cast<HookSlotKind>(encoded_kind);
    return true;
}

void listener_on_enter(GumInvocationContext *context, gpointer user)
{
    auto *listener = reinterpret_cast<Listener *>(user);
    RtGumInvocation invocation{};
    unsigned long original_args[8]{};
    invocation.context = reinterpret_cast<unsigned long>(context);
    invocation.function = listener->function_address;
    for (unsigned int index = 0; index < 8U; ++index) {
        original_args[index] = reinterpret_cast<unsigned long>(
            gum_invocation_context_get_nth_argument(context, index));
        invocation.args[index] = original_args[index];
    }
    invocation.system_error = static_cast<unsigned int>(context->system_error);
    if (listener->on_enter != nullptr)
        listener->on_enter(&invocation, listener->user_data);
    for (unsigned int index = 0; index < 8U; ++index) {
        if (invocation.args[index] == original_args[index]) continue;
        gum_invocation_context_replace_nth_argument(
            context, index, reinterpret_cast<gpointer>(invocation.args[index]));
    }
    context->system_error = static_cast<gint>(invocation.system_error);
}

void listener_on_leave(GumInvocationContext *context, gpointer user)
{
    auto *listener = reinterpret_cast<Listener *>(user);
    RtGumInvocation invocation{};
    invocation.context = reinterpret_cast<unsigned long>(context);
    invocation.function = listener->function_address;
    invocation.return_value = reinterpret_cast<unsigned long>(
        gum_invocation_context_get_return_value(context));
    const unsigned long original_return = invocation.return_value;
    invocation.system_error = static_cast<unsigned int>(context->system_error);
    if (listener->on_leave != nullptr)
        listener->on_leave(&invocation, listener->user_data);
    if (invocation.return_value != original_return)
        gum_invocation_context_replace_return_value(
            context, reinterpret_cast<gpointer>(invocation.return_value));
    context->system_error = static_cast<gint>(invocation.system_error);
}

long gum_find_export(const char *soname, const char *symbol, unsigned long *out_address)
{
    if (!soname || !symbol || !out_address) return -22;
    *out_address = 0;
    if (g_host != nullptr && g_host->find_export != nullptr) {
        const long status = g_host->find_export(soname, symbol, out_address);
        if (status == 0 && *out_address != 0UL) return 0;
        *out_address = 0UL;
    }
    GError *error = nullptr;
    GumModule *module = gum_module_load(soname, &error);
    if (!module) {
        if (error != nullptr) g_error_free(error);
        return -2;
    }
    const GumAddress address = gum_module_find_export_by_name(module, symbol);
    g_object_unref(module);
    if (address == 0) return -2;
    *out_address = static_cast<unsigned long>(address);
    return 0;
}

long gum_attach(gpointer target,
                void (*on_enter)(RtGumInvocation *, void *),
                void (*on_leave)(RtGumInvocation *, void *),
                void *user_data,
                unsigned long *out_handle)
{
    if (!g_interceptor || !target || !out_handle) return -22;
    *out_handle = 0;
    ghost_log("rtgum-gum: attach allocate listener");
    auto *listener = static_cast<Listener *>(malloc(sizeof(Listener)));
    if (!listener) return -12;
    listener->on_enter = on_enter;
    listener->on_leave = on_leave;
    listener->user_data = user_data;
    listener->function_address = reinterpret_cast<unsigned long>(target);
    GumInvocationListener *call_listener = gum_make_call_listener(
        listener_on_enter, listener_on_leave, listener,
        reinterpret_cast<GDestroyNotify>(free));
    if (call_listener == nullptr) {
        free(listener);
        return -12;
    }
    /* The Lua arming worker may be classified as a Gum internal thread when
     * gum_init_embedded() is first entered from that pthread. An ordinary
     * listener is suppressed on ignored threads, which made the exact-target
     * smoke call execute without producing evidence. User requested hooks
     * must observe target calls regardless of Gum's internal-thread marker. */
    GumAttachOptions options{};
    options.ignorability = GUM_INVOCATION_UNIGNORABLE;
    /* Reserve before attaching so concurrent callers cannot select the same
     * slot. Keep the caller's ref: the interceptor only borrows the pointer,
     * and the destroy notify runs when the last ref drops after detach. */
    unsigned long handle = 0UL;
    ListenerSlot *slot = reserve_listener_slot(kHookSlotListener, &handle);
    if (!slot) {
        g_object_unref(call_listener);
        return -12;
    }

    ghost_log("rtgum-gum: attach interceptor begin");
    const GumAttachReturn reserved_result =
        gum_interceptor_attach(g_interceptor, target, call_listener, &options);
    ghost_log("rtgum-gum: attach interceptor end");
    if (reserved_result != GUM_ATTACH_OK) {
        release_listener_slot_reservation(slot, handle);
        g_object_unref(call_listener);
        return -22;
    }
    listener_slots_lock();
    slot->call_listener = call_listener;
    slot->target = reinterpret_cast<unsigned long>(target);
    slot->state = kHookSlotActive;
    listener_slots_unlock();
    *out_handle = handle;
    return 0;
}

long gum_intercept_attach(const char *soname,
                          const char *symbol,
                          void (*on_enter)(RtGumInvocation *, void *),
                          void (*on_leave)(RtGumInvocation *, void *),
                          void *user_data,
                          unsigned long *out_handle)
{
    if (!soname || !symbol) return -22;
    GError *error = nullptr;
    GumModule *module = gum_module_load(soname, &error);
    if (!module) {
        if (error != nullptr) g_error_free(error);
        return -2;
    }
    const GumAddress address = gum_module_find_export_by_name(module, symbol);
    g_object_unref(module);
    if (address == 0) return -2;
    return gum_attach(reinterpret_cast<gpointer>(static_cast<unsigned long>(address)),
                      on_enter,
                      on_leave,
                      user_data,
                      out_handle);
}

long gum_intercept_attach_address(unsigned long address,
                                  void (*on_enter)(RtGumInvocation *, void *),
                                  void (*on_leave)(RtGumInvocation *, void *),
                                  void *user_data,
                                  unsigned long *out_handle)
{
    if (address == 0) return -22;
    return gum_attach(reinterpret_cast<gpointer>(address),
                      on_enter,
                      on_leave,
                      user_data,
                      out_handle);
}

long gum_intercept_revert(unsigned long handle)
{
    if (!g_interceptor) return -22;
    std::size_t slot_index = 0U;
    HookSlotKind encoded_kind = kHookSlotListener;
    if (!hook_handle_shape_valid(handle, &slot_index, &encoded_kind)) return -22;

    GumInvocationListener *call_listener = nullptr;
    unsigned long target = 0UL;
    listener_slots_lock();
    ListenerSlot &slot = g_listener_slots[slot_index];
    if (slot.state != kHookSlotActive || slot.handle != handle ||
        slot.kind != encoded_kind) {
        listener_slots_unlock();
        return -2;
    }
    if ((encoded_kind == kHookSlotListener && slot.call_listener == nullptr) ||
        (encoded_kind == kHookSlotReplacement && slot.target == 0UL)) {
        slot = ListenerSlot{};
        listener_slots_unlock();
        return -2;
    }
    slot.state = kHookSlotRetiring;
    call_listener = slot.call_listener;
    target = slot.target;
    listener_slots_unlock();

    if (encoded_kind == kHookSlotListener) {
        gum_interceptor_detach(g_interceptor, call_listener);
        g_object_unref(call_listener);
    } else {
        gum_interceptor_revert(g_interceptor,
                               reinterpret_cast<gpointer>(target));
    }

    listener_slots_lock();
    if (slot.state == kHookSlotRetiring && slot.handle == handle)
        slot = ListenerSlot{};
    listener_slots_unlock();
    return 0;
}

long gum_replace(unsigned long target,
                 unsigned long replacement,
                 unsigned long *out_original,
                 unsigned long *out_handle)
{
    if (!g_interceptor || target == 0 || replacement == 0 ||
        !out_original || !out_handle)
        return -22;
    *out_original = 0;
    *out_handle = 0;
    unsigned long handle = 0UL;
    ListenerSlot *slot = reserve_listener_slot(kHookSlotReplacement, &handle);
    if (slot == nullptr) return -12;
    gpointer original = nullptr;
    const GumReplaceReturn result = gum_interceptor_replace(
        g_interceptor,
        reinterpret_cast<gpointer>(target),
        reinterpret_cast<gpointer>(replacement),
        &original,
        nullptr);
    if (result != GUM_REPLACE_OK) {
        release_listener_slot_reservation(slot, handle);
        return -22;
    }
    listener_slots_lock();
    slot->target = target;
    slot->state = kHookSlotActive;
    listener_slots_unlock();
    *out_original = reinterpret_cast<unsigned long>(original);
    *out_handle = handle;
    return 0;
}

long gum_memory_read(unsigned long address, void *buffer, unsigned long length)
{
    if (address == 0 || !buffer || length == 0 || address + length < address)
        return -22;
    GhostAllocation allocation{};
    if (!find_ghost_allocation(address, true, allocation)) {
        if (g_host != nullptr && g_host->memory_read != nullptr) {
            auto *output = static_cast<unsigned char *>(buffer);
            unsigned long copied = 0UL;
            while (copied < length) {
                unsigned long chunk = length - copied;
                if (chunk > 4096UL) chunk = 4096UL;
                const long status = g_host->memory_read(
                    address + copied, output + copied, chunk);
                if (status != 0) return status;
                copied += chunk;
            }
            return 0;
        }
    } else {
        if (address + length > allocation.address + allocation.span_size ||
            (allocation.protection & 1U) == 0U)
            return -13;
    }
    const volatile unsigned char *source =
        reinterpret_cast<const volatile unsigned char *>(address);
    auto *output = static_cast<unsigned char *>(buffer);
    for (unsigned long index = 0; index < length; ++index) output[index] = source[index];
    return 0;
}

long gum_memory_write(unsigned long address, const void *buffer, unsigned long length)
{
    if (address == 0 || !buffer || length == 0 || address + length < address)
        return -22;
    GhostAllocation allocation{};
    if (!find_ghost_allocation(address, true, allocation)) {
        if (g_host != nullptr && g_host->memory_write != nullptr) {
            const auto *input = static_cast<const unsigned char *>(buffer);
            unsigned long copied = 0UL;
            while (copied < length) {
                unsigned long chunk = length - copied;
                if (chunk > 4096UL) chunk = 4096UL;
                const long status = g_host->memory_write(
                    address + copied, input + copied, chunk);
                if (status != 0) return status;
                copied += chunk;
            }
            return 0;
        }
    } else {
        if (address + length > allocation.address + allocation.span_size ||
            (allocation.protection & 2U) == 0U)
            return -13;
    }
    volatile unsigned char *destination =
        reinterpret_cast<volatile unsigned char *>(address);
    const auto *input = static_cast<const unsigned char *>(buffer);
    for (unsigned long index = 0; index < length; ++index) destination[index] = input[index];
    return 0;
}

long gum_memory_alloc(unsigned long size, unsigned long *out_address)
{
    if (!out_address || size == 0) return -22;
    return allocate_ghost_span(size, 3 /* Read | Write */, out_address);
}

long gum_memory_free(unsigned long address)
{
    if (address == 0) return -22;
    return release_ghost_span(address, 0UL);
}

/* Gum's Linux backend normally edits executable file mappings by changing
 * them to RW and back to RX. Android SELinux labels that transition execmod
 * and aborts an untrusted app. Keep a process-private model of the desired
 * code view, let Gum edit an RW ghost copy, and commit only changed ARM64
 * words through the KPM. The clean VMA page is never made writable. */
constexpr unsigned long kCodePatchPageSize = 4096UL;
constexpr unsigned int kMaximumCodePatchPages = 32U;
constexpr unsigned int kMaximumCodePatchRecords = 16U;
constexpr unsigned int kMaximumCodePatchPlans = 16U;

struct CodePatchRecord {
    unsigned short offset = 0U;
    unsigned short length = 0U;
    bool active = false;
};

struct CodePatchPage {
    unsigned long target_page = 0UL;
    bool active = false;
    bool ghost_target = false;
    CodePatchRecord records[kMaximumCodePatchRecords]{};
    alignas(16) unsigned char clean[kCodePatchPageSize]{};
    alignas(16) unsigned char desired[kCodePatchPageSize]{};
};

struct CodePatchPlan {
    unsigned short offset = 0U;
    unsigned short length = 0U;
    unsigned char record_index = 0U;
    bool existing = false;
    bool unpatch = false;
};

CodePatchPage g_code_patch_pages[kMaximumCodePatchPages]{};
std::atomic_flag g_code_patch_lock = ATOMIC_FLAG_INIT;
thread_local bool g_code_patch_active = false;

void code_patch_lock()
{
    while (g_code_patch_lock.test_and_set(std::memory_order_acquire))
        asm volatile("yield" ::: "memory");
}

void code_patch_unlock()
{
    g_code_patch_lock.clear(std::memory_order_release);
}

bool bytes_equal(const unsigned char *left, const unsigned char *right,
                 unsigned long length)
{
    for (unsigned long index = 0UL; index < length; ++index)
        if (left[index] != right[index]) return false;
    return true;
}

bool code_patch_callbacks_ready()
{
    return g_host != nullptr && g_host->code_read_clean != nullptr &&
           g_host->ghost_code_write != nullptr &&
           g_host->shadow_code_patch != nullptr &&
           g_host->shadow_code_unpatch != nullptr;
}

CodePatchPage *code_patch_page_for(unsigned long target_page)
{
    for (CodePatchPage &page : g_code_patch_pages)
        if (page.active && page.target_page == target_page) return &page;

    CodePatchPage *slot = nullptr;
    for (CodePatchPage &page : g_code_patch_pages)
        if (!page.active) {
            slot = &page;
            break;
        }
    if (slot == nullptr || !code_patch_callbacks_ready()) return nullptr;

    GhostAllocation allocation{};
    const bool ghost_target =
        find_ghost_allocation(target_page, true, allocation);
    *slot = {};
    long status = 0;
    if (ghost_target) {
        /* Owned RX pages retain EL0 read permission. Reading them directly
         * avoids asking GUP to pin a VMA-less address. */
        memcpy(slot->clean, reinterpret_cast<const void *>(target_page),
               kCodePatchPageSize);
    } else {
        status = g_host->code_read_clean(target_page, slot->clean,
                                         kCodePatchPageSize);
    }
    if (status != 0) {
        char message[128]{};
        snprintf(message, sizeof(message),
                 "rtgum-gum: clean read failed rc=%ld page=0x%lx",
                 status, target_page);
        ghost_log(message);
        return nullptr;
    }
    memcpy(slot->desired, slot->clean, kCodePatchPageSize);
    slot->ghost_target = ghost_target;
    slot->target_page = target_page;
    slot->active = true;
    return slot;
}

bool range_changed(const unsigned char *before, const unsigned char *after,
                   unsigned int offset, unsigned int length)
{
    return !bytes_equal(before + offset, after + offset, length);
}

bool commit_ghost_code_page(CodePatchPage &page,
                            const unsigned char *updated)
{
    struct GhostWritePlan {
        unsigned short offset;
        unsigned short length;
    } plans[8]{};
    unsigned int first_word = kCodePatchPageSize / 4UL;
    unsigned int last_word = 0U;
    for (unsigned int word = 0U; word < kCodePatchPageSize / 4UL; ++word) {
        if (!range_changed(page.desired, updated, word * 4U, 4U)) continue;
        if (first_word == kCodePatchPageSize / 4UL) first_word = word;
        last_word = word;
    }
    if (first_word == kCodePatchPageSize / 4UL) return true;

    /* Kernel-alias writes may safely include unchanged bytes. Coalescing the
     * full changed envelope avoids exhausting a plan on generated thunk pages
     * whose instruction/data islands alternate many small changed runs. */
    unsigned int plan_count = 0U;
    unsigned int offset = first_word * 4U;
    unsigned int remaining = (last_word - first_word + 1U) * 4U;
    while (remaining != 0U) {
        const unsigned int amount = remaining > 512U ? 512U : remaining;
        plans[plan_count++] = {
            static_cast<unsigned short>(offset),
            static_cast<unsigned short>(amount)};
        offset += amount;
        remaining -= amount;
    }

    unsigned int completed = 0U;
    for (; completed < plan_count; ++completed) {
        const GhostWritePlan &plan = plans[completed];
        const long status = g_host->ghost_code_write(
            page.target_page + plan.offset, updated + plan.offset,
            plan.length);
        if (status != 0) {
            char message[128]{};
            snprintf(message, sizeof(message),
                     "rtgum-gum: ghost commit failed rc=%ld page=0x%lx off=0x%x len=%u",
                     status, page.target_page, plan.offset, plan.length);
            ghost_log(message);
            break;
        }
    }
    if (completed != plan_count) {
        while (completed != 0U) {
            const GhostWritePlan &plan = plans[--completed];
            (void)g_host->ghost_code_write(page.target_page + plan.offset,
                                           page.desired + plan.offset,
                                           plan.length);
        }
        return false;
    }

    /* gum_memory_patch_code() is also used for standalone thunk pages.  Gum
     * allocates those pages RW and relies on its normal patch backend to
     * finish the transaction as RX.  Our ghost patch path bypasses that
     * backend, so leaving the allocation RW makes the first branch into the
     * thunk fail with an EL0 instruction abort.  Promote the complete logical
     * allocation after the kernel-alias writes are committed.  Subsequent
     * edits remain possible through ghost_code_write(), without reopening an
     * executable userspace mapping for write access. */
    GhostAllocation allocation{};
    if (!find_ghost_allocation(page.target_page, true, allocation)) {
        ghost_log("rtgum-gum: patched ghost allocation disappeared");
        return false;
    }
    const long protect_status = g_host->ghost_protect_span != nullptr
        ? g_host->ghost_protect_span(allocation.address,
                                     allocation.span_size,
                                     5U /* Read | Execute */)
        : g_host->ghost_protect != nullptr
              ? g_host->ghost_protect(allocation.address,
                                      5U /* Read | Execute */)
              : -95;
    if (protect_status != 0) {
        char message[144]{};
        snprintf(message, sizeof(message),
                 "rtgum-gum: ghost code finalize failed rc=%ld base=0x%lx span=0x%lx",
                 protect_status, allocation.address, allocation.span_size);
        ghost_log(message);
        return false;
    }
    update_ghost_allocation_protection(allocation.address,
                                       5U /* Read | Execute */);
    memcpy(page.desired, updated, kCodePatchPageSize);
    return true;
}

bool commit_shadow_code_page(CodePatchPage &page,
                             const unsigned char *updated)
{
    CodePatchPlan plans[kMaximumCodePatchPlans]{};
    bool handled[kCodePatchPageSize / 4UL]{};
    bool reserved[kMaximumCodePatchRecords]{};
    unsigned int plan_count = 0U;

    /* Existing ranges retain their identity. This makes detach/revert exact
     * even when the replacement bytes happen to equal part of the clean
     * instruction stream. */
    for (unsigned int index = 0U; index < kMaximumCodePatchRecords; ++index) {
        const CodePatchRecord &record = page.records[index];
        if (!record.active ||
            !range_changed(page.desired, updated, record.offset,
                           record.length))
            continue;
        if (plan_count == kMaximumCodePatchPlans) return false;
        CodePatchPlan &plan = plans[plan_count++];
        plan.offset = record.offset;
        plan.length = record.length;
        plan.record_index = static_cast<unsigned char>(index);
        plan.existing = true;
        plan.unpatch = bytes_equal(updated + record.offset,
                                   page.clean + record.offset,
                                   record.length);
        const unsigned int first = record.offset / 4U;
        const unsigned int last = (record.offset + record.length + 3U) / 4U;
        for (unsigned int word = first; word < last; ++word)
            handled[word] = true;
    }

    /* New redirects are represented as aligned runs no larger than the KPM's
     * atomic 32-byte patch limit. */
    unsigned int word = 0U;
    while (word < kCodePatchPageSize / 4UL) {
        const unsigned int offset = word * 4U;
        if (handled[word] ||
            !range_changed(page.desired, updated, offset, 4U)) {
            ++word;
            continue;
        }
        const unsigned int begin = word;
        unsigned int words = 0U;
        while (word < kCodePatchPageSize / 4UL && words < 8U &&
               !handled[word] &&
               range_changed(page.desired, updated, word * 4U, 4U)) {
            ++word;
            ++words;
        }
        unsigned int record_index = kMaximumCodePatchRecords;
        for (unsigned int candidate = 0U;
             candidate < kMaximumCodePatchRecords; ++candidate) {
            if (!page.records[candidate].active && !reserved[candidate]) {
                record_index = candidate;
                break;
            }
        }
        if (record_index == kMaximumCodePatchRecords ||
            plan_count == kMaximumCodePatchPlans)
            return false;
        reserved[record_index] = true;
        CodePatchPlan &plan = plans[plan_count++];
        plan.offset = static_cast<unsigned short>(begin * 4U);
        plan.length = static_cast<unsigned short>(words * 4U);
        plan.record_index = static_cast<unsigned char>(record_index);
    }

    unsigned int completed = 0U;
    for (; completed < plan_count; ++completed) {
        const CodePatchPlan &plan = plans[completed];
        const long status = plan.unpatch
            ? g_host->shadow_code_unpatch(page.target_page + plan.offset,
                                          plan.length)
            : g_host->shadow_code_patch(page.target_page + plan.offset,
                                        updated + plan.offset,
                                        plan.length);
        if (status != 0) {
            char message[144]{};
            snprintf(message, sizeof(message),
                     "rtgum-gum: shadow commit failed rc=%ld page=0x%lx off=0x%x len=%u undo=%u",
                     status, page.target_page, plan.offset, plan.length,
                     plan.unpatch ? 1U : 0U);
            ghost_log(message);
            break;
        }
    }
    if (completed != plan_count) {
        while (completed != 0U) {
            const CodePatchPlan &plan = plans[--completed];
            if (plan.existing) {
                (void)g_host->shadow_code_patch(
                    page.target_page + plan.offset,
                    page.desired + plan.offset, plan.length);
            } else {
                (void)g_host->shadow_code_unpatch(
                    page.target_page + plan.offset, plan.length);
            }
        }
        return false;
    }

    for (unsigned int index = 0U; index < plan_count; ++index) {
        const CodePatchPlan &plan = plans[index];
        CodePatchRecord &record = page.records[plan.record_index];
        if (plan.unpatch) {
            record = {};
        } else if (!plan.existing) {
            record.offset = plan.offset;
            record.length = plan.length;
            record.active = true;
        }
    }
    memcpy(page.desired, updated, kCodePatchPageSize);
    return true;
}

bool commit_code_page(CodePatchPage &page, const unsigned char *updated)
{
    if (bytes_equal(page.desired, updated, kCodePatchPageSize)) return true;
    const bool committed = page.ghost_target
        ? commit_ghost_code_page(page, updated)
        : commit_shadow_code_page(page, updated);
    if (!committed) return false;

    bool has_records = false;
    for (const CodePatchRecord &record : page.records)
        if (record.active) {
            has_records = true;
            break;
        }
    if (!has_records &&
        bytes_equal(page.clean, page.desired, kCodePatchPageSize))
        page = {};
    return true;
}

gboolean patch_code_pages_ghost(GPtrArray *addresses, gboolean coalesce,
                                GumMemoryPatchPagesApplyFunc apply,
                                gpointer apply_data)
{
    if (addresses == nullptr || apply == nullptr) return FALSE;
    if (addresses->len == 0U) return TRUE;
    if (!code_patch_callbacks_ready() || g_code_patch_active) return FALSE;

    g_code_patch_active = true;
    code_patch_lock();
    bool success = true;
    guint index = 0U;
    while (success && index < addresses->len) {
        const unsigned long target = reinterpret_cast<unsigned long>(
            g_ptr_array_index(addresses, index));
        if (target == 0UL || (target & (kCodePatchPageSize - 1UL)) != 0UL) {
            success = false;
            break;
        }
        guint page_count = 1U;
        if (coalesce) {
            while (index + page_count < addresses->len) {
                const unsigned long next = reinterpret_cast<unsigned long>(
                    g_ptr_array_index(addresses, index + page_count));
                if (next != target + page_count * kCodePatchPageSize) break;
                ++page_count;
            }
        }
        const unsigned long span =
            static_cast<unsigned long>(page_count) * kCodePatchPageSize;
        unsigned long alias_address = 0UL;
        const long allocation_status =
            allocate_ghost_span(span, 3U /* RW */, &alias_address);
        if (allocation_status != 0 || alias_address == 0UL) {
            char message[128]{};
            snprintf(message, sizeof(message),
                     "rtgum-gum: patch alias failed rc=%ld pages=%u",
                     allocation_status, page_count);
            ghost_log(message);
            success = false;
            break;
        }

        auto *alias = reinterpret_cast<unsigned char *>(alias_address);
        CodePatchPage *states[kMaximumCodePatchPages]{};
        if (page_count > kMaximumCodePatchPages) {
            ghost_log("rtgum-gum: patch span exceeds state capacity");
            success = false;
        } else {
            for (guint page_index = 0U; page_index < page_count; ++page_index) {
                CodePatchPage *state = code_patch_page_for(
                    target + page_index * kCodePatchPageSize);
                if (state == nullptr) {
                    success = false;
                    break;
                }
                states[page_index] = state;
                memcpy(alias + page_index * kCodePatchPageSize,
                       state->desired, kCodePatchPageSize);
            }
        }
        if (success) {
            apply(alias, reinterpret_cast<gpointer>(target), page_count,
                  apply_data);
            for (guint page_index = 0U; page_index < page_count; ++page_index) {
                if (!commit_code_page(
                        *states[page_index],
                        alias + page_index * kCodePatchPageSize)) {
                    success = false;
                    break;
                }
            }
        }
        if (release_ghost_span(alias_address, span) != 0) success = false;
        index += page_count;
    }
    code_patch_unlock();
    g_code_patch_active = false;
    if (!success) ghost_log("rtgum-gum: shadow code commit failed");
    return success ? TRUE : FALSE;
}

struct SingleCodePatchContext {
    gsize page_offset;
    GumMemoryPatchApplyFunc apply;
    gpointer user_data;
};

void apply_single_code_patch(gpointer memory, gpointer, guint,
                             gpointer user_data)
{
    auto *context = static_cast<SingleCodePatchContext *>(user_data);
    context->apply(static_cast<unsigned char *>(memory) + context->page_offset,
                   context->user_data);
}

} // namespace

extern "C" gboolean __real_gum_memory_patch_code(
    gpointer, gsize, GumMemoryPatchApplyFunc, gpointer);
extern "C" gboolean __real_gum_memory_patch_code_pages(
    GPtrArray *, gboolean, GumMemoryPatchPagesApplyFunc, gpointer);

extern "C" gboolean __wrap_gum_memory_patch_code(
    gpointer address, gsize size, GumMemoryPatchApplyFunc apply,
    gpointer apply_data)
{
    if (!g_ghost_memory_enabled)
        return __real_gum_memory_patch_code(address, size, apply, apply_data);
    if (address == nullptr || size == 0U || apply == nullptr) return FALSE;
    const unsigned long raw = reinterpret_cast<unsigned long>(address);
    if (raw + size < raw) return FALSE;
    const unsigned long start = raw & ~(kCodePatchPageSize - 1UL);
    const unsigned long end = (raw + size - 1UL) &
                              ~(kCodePatchPageSize - 1UL);
    GPtrArray *pages = g_ptr_array_new();
    if (pages == nullptr) return FALSE;
    for (unsigned long page = start;; page += kCodePatchPageSize) {
        g_ptr_array_add(pages, reinterpret_cast<gpointer>(page));
        if (page == end) break;
    }
    SingleCodePatchContext context{
        static_cast<gsize>(raw - start), apply, apply_data};
    const gboolean result = patch_code_pages_ghost(
        pages, TRUE, apply_single_code_patch, &context);
    g_ptr_array_unref(pages);
    return result;
}

extern "C" gboolean __wrap_gum_memory_patch_code_pages(
    GPtrArray *addresses, gboolean coalesce,
    GumMemoryPatchPagesApplyFunc apply, gpointer apply_data)
{
    return g_ghost_memory_enabled
        ? patch_code_pages_ghost(addresses, coalesce, apply, apply_data)
        : __real_gum_memory_patch_code_pages(addresses, coalesce, apply,
                                             apply_data);
}

/* Android normally reports full RWX support, but a ghost allocation is
 * deliberately governed by the KPM's W^X policy.  Gum's code allocator must
 * therefore build trampolines in RW pages and commit them as RX.  Wrapping
 * both entry-points matters: gumcodeallocator.c calls the boolean helper,
 * while Stalker calls gum_query_rwx_support() directly. */
extern "C" gboolean __real_gum_query_is_rwx_supported(void);
extern "C" GumRwxSupport __real_gum_query_rwx_support(void);

extern "C" gboolean __wrap_gum_query_is_rwx_supported(void)
{
    return g_ghost_memory_enabled
        ? FALSE
        : __real_gum_query_is_rwx_supported();
}

extern "C" GumRwxSupport __wrap_gum_query_rwx_support(void)
{
    return g_ghost_memory_enabled
        ? GUM_RWX_NONE
        : __real_gum_query_rwx_support();
}

extern "C" gpointer __real_gum_memory_allocate_near(
    const GumAddressSpec *, gsize, gsize, GumPageProtection);

extern "C" gpointer __wrap_gum_memory_allocate_near(
    const GumAddressSpec *spec,
    gsize size,
    gsize alignment,
    GumPageProtection protection)
{
    if (!g_ghost_memory_enabled || g_host == nullptr || spec == nullptr)
        return __real_gum_memory_allocate_near(
            spec, size, alignment, protection);
    unsigned long address = 0UL;
    const long status = allocate_ghost_span_near(
        static_cast<unsigned long>(size),
        static_cast<unsigned long>(alignment),
        static_cast<unsigned int>(protection),
        reinterpret_cast<unsigned long>(spec->near_address),
        static_cast<unsigned long>(spec->max_distance),
        &address);
    if (status == 0 && address != 0UL)
        return reinterpret_cast<gpointer>(address);
    errno = status < 0 && -status <= 4095
        ? static_cast<int>(-status)
        : ENOMEM;
    return nullptr;
}

extern "C" __attribute__((visibility("default"))) void ghostEntry(void *) {}

extern "C" __attribute__((visibility("default"))) void *mmap(void *address,
                                                             size_t length,
                                                             int protection,
                                                             int flags,
                                                             int fd,
                                                             off_t offset)
{
    resolve_real_memory_functions();
    const bool anonymous = (flags & MAP_ANONYMOUS) != 0;
    if (g_ghost_memory_enabled && g_host != nullptr && anonymous) {
        /* A platform fallback would make the allocation visible in maps.  The
         * ghost allocator cannot honor exact-address/shared semantics, so
         * reject those requests explicitly instead of weakening stealth. */
        if ((flags & MAP_FIXED) != 0 || (flags & MAP_SHARED) != 0 || length == 0) {
            errno = ENOTSUP;
            return MAP_FAILED;
        }
            unsigned int ghost_protection = 0;
            if ((protection & PROT_READ) != 0) ghost_protection |= 1U;
            if ((protection & PROT_WRITE) != 0) ghost_protection |= 2U;
            if ((protection & PROT_EXEC) != 0) ghost_protection |= 4U;
        if (ghost_protection == 0U) ghost_protection = 3U;
        unsigned long ghost_address = 0;
        const long status = allocate_ghost_span(length, ghost_protection,
                                                &ghost_address);
        if (status == 0 && ghost_address != 0)
            return reinterpret_cast<void *>(ghost_address);
        errno = status < 0 && -status <= 4095 ? static_cast<int>(-status) : ENOMEM;
        return MAP_FAILED;
    }
    const MmapFn fallback = real_mmap.load(std::memory_order_acquire);
    if (fallback != nullptr)
        return fallback(address, length, protection, flags, fd, offset);
    return reinterpret_cast<void *>(
        syscall(SYS_mmap, address, length, protection, flags, fd, offset));
}

extern "C" __attribute__((visibility("default"))) int munmap(void *address,
                                                              size_t length)
{
    resolve_real_memory_functions();
    if (g_ghost_memory_enabled && g_host != nullptr) {
        GhostAllocation allocation{};
        const unsigned long base = reinterpret_cast<unsigned long>(address);
        if (find_ghost_allocation(base, false, allocation)) {
            const long status = release_ghost_span(base, length);
            if (status == 0) return 0;
            errno = status < 0 && -status <= 4095 ? static_cast<int>(-status) : EINVAL;
            return -1;
        }
    }
    const MunmapFn fallback = real_munmap.load(std::memory_order_acquire);
    if (fallback != nullptr) return fallback(address, length);
    return static_cast<int>(syscall(SYS_munmap, address, length));
}

extern "C" __attribute__((visibility("default"))) int mprotect(void *address,
                                                                size_t length,
                                                                int protection)
{
    resolve_real_memory_functions();
    const unsigned long page_address =
        reinterpret_cast<unsigned long>(address) & ~0xfffUL;
    if (g_ghost_memory_enabled && g_host != nullptr) {
        GhostAllocation allocation{};
        if (find_ghost_allocation(page_address, true, allocation)) {
            const unsigned long requested_span =
                (length + 0xfffUL) & ~0xfffUL;
            if (page_address != allocation.address ||
                requested_span != allocation.span_size || protection == PROT_NONE) {
                errno = ENOTSUP;
                return -1;
            }
            unsigned int ghost_protection = 0;
            if ((protection & PROT_READ) != 0) ghost_protection |= 1U;
            if ((protection & PROT_WRITE) != 0) ghost_protection |= 2U;
            if ((protection & PROT_EXEC) != 0) ghost_protection |= 4U;
            const long status = g_host->ghost_protect_span
                ? g_host->ghost_protect_span(allocation.address,
                                             allocation.span_size,
                                             ghost_protection)
                : g_host->ghost_protect
                      ? g_host->ghost_protect(allocation.address,
                                              ghost_protection)
                      : -95;
            if (status == 0) {
                update_ghost_allocation_protection(allocation.address,
                                                   ghost_protection);
                return 0;
            }
            errno = status < 0 && -status <= 4095 ? static_cast<int>(-status) : EINVAL;
            return -1;
        }
    }
    const MprotectFn fallback = real_mprotect.load(std::memory_order_acquire);
    if (fallback != nullptr) return fallback(address, length, protection);
    return static_cast<int>(
        syscall(SYS_mprotect, address, length, protection));
}

extern "C" __attribute__((visibility("default"))) long rtgum_gum_entry(
    const RtGumHost *host,
    RtGumApi *out_api)
{
    if (!host || !out_api || host->version != RTGUM_GUM_API_VERSION) return -22;
    g_host_storage = *host;
    g_host = &g_host_storage;
    g_ghost_memory_enabled =
        (g_host_storage.reserved & RTGUM_GUM_HOST_GHOST_MEMORY) != 0UL;
    if (!g_initialized) {
        ghost_log(g_ghost_memory_enabled
            ? "rtgum-gum: memory mode=ghost"
            : "rtgum-gum: memory mode=platform");
        if (g_ghost_memory_enabled)
            ghost_log("rtgum-gum: code-page policy=shadow-commit; trampoline=rw-to-rx");
        gum_init_embedded();
        g_interceptor = gum_interceptor_obtain();
        if (!g_interceptor) return -12;
        g_initialized = true;
        ghost_log("rtgum-gum: gum_init_embedded done");
    }
    out_api->version = RTGUM_GUM_API_VERSION;
    out_api->reserved = 0;
    out_api->find_export = gum_find_export;
    out_api->intercept_attach = gum_intercept_attach;
    out_api->intercept_attach_address = gum_intercept_attach_address;
    out_api->intercept_revert = gum_intercept_revert;
    out_api->replace = gum_replace;
    out_api->memory_read = gum_memory_read;
    out_api->memory_write = gum_memory_write;
    out_api->memory_alloc = gum_memory_alloc;
    out_api->memory_free = gum_memory_free;
    out_api->stalker_start = gum_stalker_start_current;
    out_api->stalker_invalidate = gum_stalker_invalidate_current;
    out_api->stalker_stop = gum_stalker_stop_current;
    out_api->trace_start = gum_trace_start;
    out_api->trace_stop = gum_trace_stop;
    out_api->trace_query = gum_trace_query;
    return 0;
}
