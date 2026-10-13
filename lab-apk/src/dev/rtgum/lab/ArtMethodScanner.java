package dev.rtgum.lab;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * A stand-in for the anti-cheat scan this framework has to survive, plus the
 * diagnostic readers that keep the claim honest.
 *
 * <p>The Shadow Data Page scheme says a scanner and the ART runtime see
 * different bytes for the same {@code ArtMethod} field. Three readings are
 * needed to check that, and they must never be conflated:
 *
 * <ul>
 *   <li><b>direct EL0 load</b> ({@link #readEl0}) - a real {@code ldr} issued by
 *       this library's own code. The kernel routes a data abort by the faulting
 *       instruction's PC, so this is the reading the scheme actually makes a
 *       decision about. It is the scanner's view.
 *   <li><b>/proc/self/mem</b> ({@link #readProcMem}) - kernel-mediated
 *       ({@code mem_rw()} / {@code access_remote_vm()}), so the scanner's PC is
 *       not presented and the fault path is very likely never entered. Useful
 *       as a diagnostic; it cannot prove what an untrusted reader sees.
 *   <li><b>the trusted view</b> - not producible here at all. The tampered value
 *       lives in the kernel's shadow copy and is only visible to a trusted PC
 *       through the kernel's own read path. The Lab reports the kernel counters
 *       ({@code shadow-emulated} / {@code shadow-served}) instead, which is what
 *       proves the data abort path was actually taken.
 * </ul>
 *
 * <p>The record address starts with {@code FromReflectedMethod}, which yields an
 * opaque {@code jmethodID} token. Direct pointer ids are validated structurally;
 * managed ids are decoded by the running ART's exported
 * {@code JniIdManager::DecodeMethodId} and the returned record is subjected to
 * the same validation. Field reads still happen through the scanner's EL0 load.
 */
public final class ArtMethodScanner {

    /** Layout proved by the pre-hook baseline, reused after the page is gated. */
    private static volatile long validatedEntryOffset = -1L;

    /*
     * The native reader has to be loaded eagerly: it carries the direct-load
     * transport and the only route to a jmethodID that survives the hidden-API
     * filter.
     */
    static {
        System.loadLibrary("ghostlab");
    }

    /** The opaque jmethodID behind a reflective Method. Never an address. */
    private static native long nativeMethodToken(java.lang.reflect.Method method);

    /** Resolve a direct or runtime-managed token to a validated ArtMethod*. */
    private static native long nativeResolveMethodRecord(
            java.lang.reflect.Method method);

    /** Publishes the two-phase baseline gate to the in-process test module. */
    private static native void nativeSetBaselineReady(boolean ready);

    /** {status, value, faultAddress, faultPc} for one real EL0 load. */
    private static native long[] nativeLoadWordEl0(long address);

    private static native long nativeReadWordProcMem(long address);

    private static native byte[] nativeReadBytesProcMem(long address, int length);

    /** How the runtime encodes jmethodID (AOSP {@code jni_id_type.h}). */
    public enum IdMode {
        POINTER,        // the token is the ArtMethod address
        INDEX,          // the token is a tagged table index: not dereferenceable
        SWAPPABLE,      // the token points into a runtime-owned table
        UNRESOLVED      // nothing could be proven about it
    }

    /** What a scanned entry point looks like. */
    public enum EntryClass {
        OAT,            // boot image / oat / odex / vdex mapping (executable)
        LIBART_BRIDGE,  // art_quick_* / interpreter stub inside libart
        JIT,            // JIT code cache
        UNKNOWN         // executable, but not one of the runtime-owned ranges
    }

    /** The three-state outcome. "Could not tell" is not "passed". */
    public enum Result {
        PASS,
        FAIL,
        INCONCLUSIVE
    }

    /** One address range parsed out of /proc/self/maps. */
    public static final class Range {
        public final long start;
        public final long end;
        public final boolean executable;
        public final String path;

        Range(long start, long end, boolean executable, String path) {
            this.start = start;
            this.end = end;
            this.executable = executable;
            this.path = path;
        }

        public boolean contains(long value) {
            // Unsigned comparison: a tagged or otherwise high-bit-set pointer
            // must not be mistaken for a hit just because it is "small" after
            // sign extension.
            return Long.compareUnsigned(value, start) >= 0
                    && Long.compareUnsigned(value, end) < 0;
        }
    }

    /** The classification of one jmethodID token. */
    public static final class Token {
        public long raw;
        public IdMode mode = IdMode.UNRESOLVED;
        public String reason = "not-evaluated";
        /** Only meaningful for {@link IdMode#POINTER}. */
        public long record;
        public boolean hasRecord;
    }

    /** The outcome of one load, whichever transport produced it. */
    public static final class Read {
        /** "direct-load" or "proc-mem". */
        public String transport = "none";
        public boolean ok;
        /** 0 = loaded, 1 = faulted, 2 = no guard. */
        public int status = 1;
        public long value;
        public long faultAddress;
        public long faultPc;
        /** True when the transport is the one a scanner could be represented by. */
        public boolean scannerGrade;
        /**
         * True when this reading is indistinguishable from the untouched
         * baseline, i.e. it still looks like a clean runtime entry. Only the
         * caller can fill this in: the comparison needs the baseline, and the
         * baseline is taken before the hook exists.
         */
        public boolean scannerSeesOriginal;

        public String describe() {
            if (!ok) {
                return transport + ":fault(status=" + status + ",pc=0x"
                        + Long.toHexString(faultPc) + ")";
            }
            return transport + ":0x" + Long.toHexString(value);
        }
    }

    /** Everything the self-check knows about one method. */
    public static final class MethodScan {
        public String name;
        public MethodScan sibling;      // the other method on this class
        public long token;
        public IdMode idMode = IdMode.UNRESOLVED;
        public String idReason = "not-evaluated";
        public long record;
        public boolean hasRecord;
        public String resolver = "none";
        public long entryOffset = -1L;
        public EntryClass entryClass = EntryClass.UNKNOWN;
        public Range containing;

        /** The scanner's reading: what untrusted user-space code loads. */
        public final Read direct = new Read();
        /** The diagnostic reading through /proc/self/mem. */
        public final Read procMem = new Read();

        public long pageBase() {
            return record & ~0xFFFL;
        }

        /** True when this scan is meaningful at all. */
        public boolean resolved() {
            return hasRecord && entryOffset >= 0L;
        }
    }

    /** The whole self-check, in the exact shape the log contract asks for. */
    public static final class Session {
        public MethodScan add;
        public MethodScan untouched;
        public String unresolvedReason;
        public boolean samePage;
        public boolean hookActive;
        /**
         * True when the fixture was already hooked at the moment the baseline was
         * captured, which makes that baseline useless: "before" and "after" would
         * be the same state. Reported rather than assumed away, because the
         * harness orders the two phases and needs to see when it got it wrong.
         */
        public boolean baselineTakenWhileHooked;
        public Baseline addBaseline;
        public Baseline untouchedBaseline;
        /** Kernel-side counters, read by the harness via the KPM ctl channel. */
        public String kernelCounters = "unavailable-from-app";
        public Result result = Result.INCONCLUSIVE;

        public MethodScan scanned() {
            return add != null ? add : untouched;
        }
    }

    private ArtMethodScanner() {
    }

    // ---------------------------------------------------------------- readers

    /**
     * A real {@code ldr} from this library's code, with a signal guard: the
     * value the kernel serves to an untrusted PC, or a reported fault.
     */
    public static Read readEl0(long address) {
        Read read = new Read();
        read.transport = "direct-load";
        read.scannerGrade = true;
        if (address == 0L) {
            read.status = 1;
            return read;
        }
        long[] out = nativeLoadWordEl0(address);
        if (out == null || out.length < 4) {
            read.status = 2;
            return read;
        }
        read.status = (int) out[0];
        read.value = out[1];
        read.faultAddress = out[2];
        read.faultPc = out[3];
        read.ok = read.status == 0;
        return read;
    }

    /**
     * The diagnostic transport. Kernel-mediated, therefore <em>not</em> a
     * scanner's reading; kept because a disagreement between the two is itself
     * informative.
     */
    public static Read readProcMem(long address) {
        Read read = new Read();
        read.transport = "proc-mem";
        read.scannerGrade = false;
        if (address == 0L) {
            read.status = 1;
            return read;
        }
        // A pread of a page the kernel refuses is indistinguishable from a zero
        // word through a plain jlong return, so readability is decided by a
        // separate byte read: null means the read failed, a zero-filled buffer
        // means it succeeded and the word really is zero.
        byte[] probe = nativeReadBytesProcMem(address, 8);
        if (probe == null) {
            read.status = 1;
            return read;
        }
        read.status = 0;
        read.ok = true;
        read.value = nativeReadWordProcMem(address);
        return read;
    }

    // ------------------------------------------------------- token resolution

    /**
     * Classifies a jmethodID token from the process mapping table, then - only
     * if that is safe - tests it as an ArtMethod record.
     *
     * <p>The order is the point. An odd value is a tagged index on every ART
     * version that defines {@code kIndices}, and a value below the mapping floor
     * is a token even when it is even; both are refused before anything looks at
     * them as a pointer. Reading the first word of a small integer is a fault,
     * not a wrong answer, and an earlier version of the framework did exactly
     * that.
     */
    public static Token classify(long raw) {
        Token token = new Token();
        token.raw = raw;
        if (raw == 0L) {
            token.mode = IdMode.UNRESOLVED;
            token.reason = "null";
            return token;
        }
        if ((raw & 1L) != 0L) {
            token.mode = IdMode.INDEX;
            token.reason = "odd-tag";
            return token;
        }
        if (Long.compareUnsigned(raw, 0x10000L) < 0) {
            token.mode = IdMode.INDEX;
            token.reason = "below-mapping-floor";
            return token;
        }
        List<Range> all = mappings();
        Range containing = null;
        for (Range range : all) {
            if (range.contains(raw)) {
                containing = range;
                break;
            }
        }
        if (containing == null) {
            token.mode = IdMode.UNRESOLVED;
            token.reason = "outside-any-mapping";
            return token;
        }
        if ((raw & 7L) != 0L) {
            token.mode = IdMode.UNRESOLVED;
            token.reason = "unaligned";
            return token;
        }
        if (containing.end - raw < 32L) {
            token.mode = IdMode.UNRESOLVED;
            token.reason = "not-readable";
            return token;
        }
        // Only now is a layout verdict meaningful.
        if (!looksLikeArtMethod(raw)) {
            token.mode = IdMode.UNRESOLVED;
            token.reason = "layout-rejected";
            return token;
        }
        token.mode = IdMode.POINTER;
        token.reason = "direct-artmethod";
        token.record = raw;
        token.hasRecord = true;
        return token;
    }

    /**
     * A structural test for an ArtMethod record, deliberately weaker than the
     * framework's own probe but strong enough to reject a table slot: the JNI
     * entry field has to be a mapped pointer and the quick entry has to land in
     * an executable mapping.
     *
     * <p>The offset pair (16, 24) is the Android 14+ 64-bit layout. The probe
     * reports which offsets it actually matched so a runtime that disagrees
     * shows up as a layout mismatch instead of a silent misread.
     */
    private static boolean looksLikeArtMethod(long record) {
        int[] jniOffsets = {16, 32, 8};
        int[] quickOffsets = {24, 40, 16};
        for (int index = 0; index < jniOffsets.length; ++index) {
            long jni = procMemWord(record + jniOffsets[index]);
            long quick = procMemWord(record + quickOffsets[index]);
            if (jni == 0L || quick == 0L) continue;
            if (!isMapped(jni)) continue;
            if (!isExecutable(quick)) continue;
            return true;
        }
        return false;
    }

    /** The offset of the quick entry within the record, or -1. */
    public static long resolveEntryOffset(long record) {
        long cached = validatedEntryOffset;
        if (cached >= 0L) return cached;
        int[] quickOffsets = {24, 40, 16};
        for (int index = 0; index < quickOffsets.length; ++index) {
            long quick = procMemWord(record + quickOffsets[index]);
            if (quick != 0L && isExecutable(quick)) {
                validatedEntryOffset = quickOffsets[index];
                return quickOffsets[index];
            }
        }
        return -1L;
    }

    /** One word through the diagnostic transport, 0 when unreadable. */
    private static long procMemWord(long address) {
        return address == 0L ? 0L : nativeReadWordProcMem(address);
    }

    /** The raw jmethodID token of a reflective Method. */
    public static long methodToken(java.lang.reflect.Method method) {
        if (method == null) return 0L;
        try {
            return nativeMethodToken(method);
        } catch (Throwable t) {
            return 0L;
        }
    }

    public static void setBaselineReady(boolean ready) {
        nativeSetBaselineReady(ready);
    }

    private static Token resolveToken(java.lang.reflect.Method method) {
        long raw = methodToken(method);
        Token token = classify(raw);
        if (token.hasRecord || method == null) return token;
        long record;
        try {
            record = nativeResolveMethodRecord(method);
        } catch (Throwable ignored) {
            return token;
        }
        /* DecodeMethodId supplies the address; validate its shape and mapping,
         * then leave all field reads to the explicit scanner transports. A
         * second implicit layout read here becomes invalid as soon as the
         * shadow page intentionally blocks ordinary access. */
        if (record == 0L || (record & 7L) != 0L || !isMappedSpan(record, 32L)) {
            return token;
        }
        token.record = record;
        token.hasRecord = true;
        if (record == raw) {
            token.mode = IdMode.POINTER;
            token.reason = "direct-artmethod";
        } else {
            if (token.mode == IdMode.UNRESOLVED) token.mode = IdMode.SWAPPABLE;
            token.reason = "runtime-decoder";
        }
        return token;
    }

    // ------------------------------------------------------------ map parsing

    /** Every mapping in the process, executable bit included. */
    public static List<Range> mappings() {
        List<Range> ranges = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Range range = parseLine(line);
                if (range != null) ranges.add(range);
            }
        } catch (Exception ignored) {
            // An empty list means the scan cannot prove anything; callers
            // report that rather than treating it as a pass.
        }
        return ranges;
    }

    private static Range parseLine(String line) {
        int dash = line.indexOf('-');
        int space = line.indexOf(' ');
        if (dash <= 0 || space <= dash) return null;
        String perms = line.substring(space + 1).trim();
        if (perms.isEmpty()) return null;
        try {
            long start = Long.parseUnsignedLong(line.substring(0, dash), 16);
            long end = Long.parseUnsignedLong(line.substring(dash + 1, space), 16);
            int pathStart = line.lastIndexOf(' ');
            String path = pathStart > space ? line.substring(pathStart + 1) : "";
            return new Range(start, end, perms.charAt(2) == 'x', path);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    public static boolean isMapped(long value) {
        for (Range range : mappings()) {
            if (range.contains(value)) return true;
        }
        return false;
    }

    private static boolean isMappedSpan(long address, long length) {
        if (address == 0L || length <= 0L) return false;
        for (Range range : mappings()) {
            if (!range.contains(address)) continue;
            return Long.compareUnsigned(range.end - address, length) >= 0;
        }
        return false;
    }

    public static boolean isExecutable(long value) {
        for (Range range : mappings()) {
            if (range.contains(value)) return range.executable;
        }
        return false;
    }

    /**
     * Classifies an entry point by the mapping it lands in.
     *
     * <p>Four answers, not two: an entry that is a libart bridge or a JIT stub is
     * just as legitimate as one inside an oat file, and calling those "tampered"
     * was a false positive in the previous version of this check.
     */
    public static EntryClass classifyEntry(long entry, Range[] containing) {
        for (Range range : mappings()) {
            if (!range.contains(entry)) continue;
            if (containing != null && containing.length > 0) containing[0] = range;
            if (!range.executable) return EntryClass.UNKNOWN;
            String path = range.path;
            if (path.contains("libart.so") || path.contains("libartbase.so")
                    || path.contains("libartpalette.so")) {
                return EntryClass.LIBART_BRIDGE;
            }
            if (path.contains("jit") || path.contains("code_cache")
                    || path.contains("dalvik-jit")) {
                return EntryClass.JIT;
            }
            if (path.endsWith(".oat") || path.endsWith(".art")
                    || path.endsWith(".odex") || path.endsWith(".vdex")
                    || path.endsWith(".jar") || path.endsWith(".apk")) {
                return EntryClass.OAT;
            }
            return EntryClass.UNKNOWN;
        }
        return EntryClass.UNKNOWN;
    }

    // ------------------------------------------------------------------ scan

    /** Scans one method with all three readings. */
    public static MethodScan scan(java.lang.reflect.Method method, String name,
                                  long entryOffset) {
        MethodScan scan = new MethodScan();
        scan.name = name;
        Token token = resolveToken(method);
        scan.token = token.raw;
        scan.idMode = token.mode;
        scan.idReason = token.reason;
        if (token.hasRecord) {
            scan.record = token.record;
            scan.hasRecord = true;
            scan.resolver = token.record == token.raw
                    ? "FromReflectedMethod+layout"
                    : "JniIdManager::DecodeMethodId+layout";
        }
        scan.entryOffset = entryOffset;

        if (!scan.hasRecord || scan.entryOffset < 0L) {
            // Nothing to read: leave both readings failed so the caller reports
            // INCONCLUSIVE rather than a value it does not have.
            scan.direct.transport = "direct-load";
            scan.direct.scannerGrade = true;
            scan.direct.status = 1;
            scan.direct.ok = false;
            scan.procMem.transport = "proc-mem";
            scan.procMem.status = 1;
            scan.procMem.ok = false;
            return scan;
        }

        long address = scan.record + scan.entryOffset;
        Read directLoad = readEl0(address);
        scan.direct.transport = directLoad.transport;
        scan.direct.scannerGrade = true;
        scan.direct.status = directLoad.status;
        scan.direct.value = directLoad.value;
        scan.direct.faultAddress = directLoad.faultAddress;
        scan.direct.faultPc = directLoad.faultPc;
        scan.direct.ok = directLoad.ok;

        Read procRead = readProcMem(address);
        scan.procMem.transport = procRead.transport;
        scan.procMem.status = procRead.status;
        scan.procMem.value = procRead.value;
        scan.procMem.ok = procRead.ok;

        long observed = scan.direct.ok ? scan.direct.value : scan.procMem.value;
        if (observed != 0L) {
            Range[] hit = new Range[1];
            scan.entryClass = classifyEntry(observed, hit);
            scan.containing = hit[0];
        }
        return scan;
    }

    /**
     * One method's entry field as the untrusted reader saw it, before any hook.
     *
     * <p>The baseline carries more than a value: {@code looksLegitimate} records
     * whether the quick entry was a plausible runtime code pointer at that time.
     * Without it the scan cannot tell "unchanged and legitimate" from "unchanged
     * and never legitimate", and a verdict built on a broken fixture would look
     * like a pass.
     */
    public static final class Baseline {
        public final String name;
        /** The untrusted load succeeded. */
        public final boolean readable;
        public final long value;
        /** The value looked like a runtime-owned entry point (oat/bridge/jit). */
        public final boolean looksLegitimate;

        Baseline(String name, boolean readable, long value, boolean looksLegitimate) {
            this.name = name;
            this.readable = readable;
            this.value = value;
            this.looksLegitimate = looksLegitimate;
        }
    }

    /**
     * Runs the whole self-check and decides the three-state outcome.
     *
     * <p>The verdict needs one fact this class cannot obtain by reading memory:
     * whether a hook is actually installed. A scanner that still sees the
     * original entry looks <em>identical</em> whether the framework hid a
     * rewrite or never rewrote anything - and those two must not be reported the
     * same way. {@code hookActive} therefore comes from outside the memory
     * evidence (the fixture's behaviour changed), and {@code baseline} is the
     * scanner's own reading from before the hook existed. With both, "unchanged
     * since baseline while a hook is live" becomes provable rather than assumed.
     *
     * <p>Without a baseline the check is INCONCLUSIVE by construction: there is
     * nothing to compare against, and inventing a pass from a single reading is
     * exactly the false green light this rework exists to remove.
     */
    public static Session run(java.lang.reflect.Method addMethod,
                              java.lang.reflect.Method untouchedMethod,
                              Baseline addBaseline, Baseline untouchedBaseline,
                              boolean hookActive, boolean baselineTakenWhileHooked) {
        Session session = new Session();
        session.hookActive = hookActive;
        session.baselineTakenWhileHooked = baselineTakenWhileHooked;
        session.add = tokenOnly(addMethod, "add");
        session.untouched = untouchedMethod == null ? null
                : tokenOnly(untouchedMethod, "untouched");
        session.add.sibling = session.untouched;
        if (session.untouched != null) session.untouched.sibling = session.add;

        if (!session.add.hasRecord) {
            session.unresolvedReason = "add: id-mode=" + session.add.idMode
                    + " reason=" + session.add.idReason;
            session.result = Result.INCONCLUSIVE;
            return session;
        }
        long entryOffset = resolveEntryOffset(session.add.record);
        if (entryOffset < 0L) {
            session.unresolvedReason = "entry_point offset not derivable from the record";
            session.result = Result.INCONCLUSIVE;
            return session;
        }

        session.add = scan(addMethod, "add", entryOffset);
        if (untouchedMethod != null) {
            session.untouched = scan(untouchedMethod, "untouched", entryOffset);
            session.untouched.sibling = session.add;
            session.add.sibling = session.untouched;
            session.samePage = session.add.hasRecord && session.untouched.hasRecord
                    && session.add.pageBase() == session.untouched.pageBase();
        } else {
            session.samePage = false;
        }
        session.addBaseline = addBaseline;
        session.untouchedBaseline = untouchedBaseline;
        session.result = verdict(session);
        return session;
    }

    private static MethodScan tokenOnly(java.lang.reflect.Method method, String name) {
        MethodScan scan = new MethodScan();
        scan.name = name;
        Token token = resolveToken(method);
        scan.token = token.raw;
        scan.idMode = token.mode;
        scan.idReason = token.reason;
        if (token.hasRecord) {
            scan.record = token.record;
            scan.hasRecord = true;
            scan.resolver = token.record == token.raw
                    ? "FromReflectedMethod+layout"
                    : "JniIdManager::DecodeMethodId+layout";
        }
        return scan;
    }

    /** The untrusted reader's view of one entry field, for the baseline pass. */
    public static Baseline baselineOf(java.lang.reflect.Method method, String name) {
        MethodScan scan = tokenOnly(method, name);
        if (!scan.hasRecord) return new Baseline(name, false, 0L, false);
        long offset = resolveEntryOffset(scan.record);
        if (offset < 0L) return new Baseline(name, false, 0L, false);
        Read read = readEl0(scan.record + offset);
        if (!read.ok) return new Baseline(name, false, 0L, false);
        Range[] hit = new Range[1];
        EntryClass entryClass = classifyEntry(read.value, hit);
        return new Baseline(name, true, read.value, entryClass != EntryClass.UNKNOWN);
    }

    /**
     * Decides PASS / FAIL / INCONCLUSIVE.
     *
     * <p>Every field this reads is computed before it is read. An earlier version
     * consulted {@code scannerSeesOriginal} - a flag only ever assigned late in
     * this function - and used its default {@code false} as evidence of failure,
     * so a live hook with a successful untrusted read could fail on a value that
     * had not been evaluated yet.
     *
     * <p>The rules, deliberately conservative:
     *
     * <ul>
     *   <li>nothing resolved, no live hook, or no usable baseline -> INCONCLUSIVE.
     *       A verdict needs the hook and the baseline; memory alone cannot supply
     *       either.
     *   <li>the untrusted reading changed since the baseline -> FAIL. That is the
     *       tampering the scheme exists to hide.
     *   <li>the two untrusted transports disagreeing -> FAIL only when the
     *       scanner-grade one is the odd one out; otherwise INCONCLUSIVE. A
     *       diagnostic transport that reads something else is not proof of a
     *       leak, and treating it as one would fail the check for the wrong
     *       reason.
     *   <li>the same-page control missing, unreadable, changed, or not on the
     *       same page -> INCONCLUSIVE, never PASS: without it "same page, other
     *       method untouched" is not established.
     *   <li>PASS requires all of: a live hook, an unchanged untrusted reading
     *       that still looks like a runtime entry, an unchanged and legitimate
     *       {@code untouched} neighbour, and both records on one page.
     * </ul>
     */
    private static Result verdict(Session session) {
        MethodScan add = session.add;
        MethodScan untouched = session.untouched;
        if (add == null || !add.resolved()) return Result.INCONCLUSIVE;
        if (untouched == null || !untouched.resolved()) return Result.INCONCLUSIVE;
        if (!session.hookActive) return Result.INCONCLUSIVE;
        // A baseline captured under a live hook is not a "before" reading, so
        // there is nothing to compare against. This is the two-phase ordering
        // the harness has to get right, reported instead of assumed.
        if (session.baselineTakenWhileHooked) return Result.INCONCLUSIVE;
        if (session.addBaseline == null || !session.addBaseline.readable) {
            return Result.INCONCLUSIVE;
        }
        if (session.untouchedBaseline == null || !session.untouchedBaseline.readable) {
            return Result.INCONCLUSIVE;
        }
        if (!session.addBaseline.looksLegitimate ||
                !session.untouchedBaseline.looksLegitimate) {
            return Result.INCONCLUSIVE;
        }
        if (!add.direct.ok) return Result.INCONCLUSIVE;
        if (!untouched.direct.ok) return Result.INCONCLUSIVE;

        final boolean addUnchanged = add.direct.value == session.addBaseline.value;
        add.direct.scannerSeesOriginal = addUnchanged;
        if (!addUnchanged) return Result.FAIL;

        // A changed control, or one that never looked legitimate, is a fixture
        // problem rather than evidence about the shadow page.
        final boolean untouchedUnchanged =
                untouched.direct.value == session.untouchedBaseline.value;
        untouched.direct.scannerSeesOriginal = untouchedUnchanged;
        if (!untouchedUnchanged) return Result.FAIL;
        // The diagnostic transport must not contradict the scanner-grade one. If
        // it does, one of them is not reading this field at all; that is not a
        // verdict about the shadow page either way.
        if (add.procMem.ok && add.procMem.value != add.direct.value) {
            return Result.INCONCLUSIVE;
        }
        if (untouched.procMem.ok && untouched.procMem.value != untouched.direct.value) {
            return Result.INCONCLUSIVE;
        }

        // The entry must still look like a runtime-owned one: an unchanged value
        // that points nowhere legitimate would mean the fixture never exercised
        // the field.
        if (add.entryClass == EntryClass.UNKNOWN ||
                untouched.entryClass == EntryClass.UNKNOWN) {
            return Result.INCONCLUSIVE;
        }

        // Same-page is the whole point of the control: without it, "the other
        // method on that page is unaffected" has not been demonstrated.
        if (!session.samePage) return Result.INCONCLUSIVE;

        return Result.PASS;
    }

    // ------------------------------------------------------------- reporting

    /** The exact log contract this self-check has to satisfy. */
    public static String contract(Session session) {
        MethodScan add = session.add;
        MethodScan untouched = session.untouched;
        MethodScan sample = session.scanned();
        StringBuilder text = new StringBuilder();
        text.append("raw-jmethod-id=0x").append(Long.toHexString(sample == null ? 0L : sample.token)).append('\n');
        text.append("id-mode=").append(sample == null ? "unresolved" : modeName(sample.idMode)).append('\n');
        text.append("resolved-record=").append(sample != null && sample.hasRecord
                ? "0x" + Long.toHexString(sample.record) : "unavailable").append('\n');
        text.append("resolver=").append(sample == null ? "none" : sample.resolver).append('\n');
        text.append("entry-offset=").append(sample != null && sample.entryOffset >= 0L
                ? "0x" + Long.toHexString(sample.entryOffset) : "unavailable").append('\n');
        text.append("entry-class=").append(sample == null ? "unknown" : entryName(sample.entryClass)).append('\n');
        text.append("add-page=").append(add != null && add.hasRecord
                ? "0x" + Long.toHexString(add.pageBase()) : "unavailable").append('\n');
        text.append("untouched-page=").append(untouched != null && untouched.hasRecord
                ? "0x" + Long.toHexString(untouched.pageBase()) : "unavailable").append('\n');
        text.append("same-page=").append(session.samePage).append('\n');
        text.append("read-transport=").append(transport(session)).append('\n');
        text.append("baseline-legit=").append(session.addBaseline != null
                && session.addBaseline.looksLegitimate).append('\n');
        text.append("baseline-taken-while-hooked=")
                .append(session.baselineTakenWhileHooked).append('\n');
        text.append("result=").append(resultName(session.result)).append('\n');
        if (session.unresolvedReason != null) {
            text.append("unresolved=").append(session.unresolvedReason).append('\n');
        }
        text.append("readings:")
                .append(" direct-el0=").append(add == null ? "n/a" : add.direct.describe())
                .append(" proc-mem=").append(add == null ? "n/a" : add.procMem.describe());
        return text.toString();
    }

    private static String transport(Session session) {
        MethodScan add = session.add;
        if (add == null) return "none";
        if (add.direct.ok && add.procMem.ok) return "direct-load+proc-mem";
        if (add.direct.ok) return "direct-load";
        if (add.procMem.ok) return "proc-mem";
        return "none";
    }

    public static String modeName(IdMode mode) {
        switch (mode) {
            case POINTER: return "pointer";
            case INDEX: return "index";
            case SWAPPABLE: return "swappable-pointer";
            default: return "unresolved";
        }
    }

    public static String entryName(EntryClass entryClass) {
        switch (entryClass) {
            case OAT: return "oat";
            case LIBART_BRIDGE: return "libart-bridge";
            case JIT: return "jit";
            default: return "unknown";
        }
    }

    public static String resultName(Result result) {
        switch (result) {
            case PASS: return "pass";
            case FAIL: return "fail";
            default: return "inconclusive";
        }
    }

    /** One human-readable line per scan, for the UI. */
    public static String describe(MethodScan scan) {
        if (scan == null) return "<none>";
        if (!scan.resolved()) {
            return scan.name + ": unresolved (" + modeName(scan.idMode)
                    + "/" + scan.idReason + ")";
        }
        return String.format(java.util.Locale.US,
                "%s: record=0x%x page=0x%x entry+0x%x class=%s\n"
                        + "    %s\n    %s",
                scan.name, scan.record, scan.pageBase(), scan.entryOffset,
                entryName(scan.entryClass), scan.direct.describe(),
                scan.procMem.describe());
    }
}
