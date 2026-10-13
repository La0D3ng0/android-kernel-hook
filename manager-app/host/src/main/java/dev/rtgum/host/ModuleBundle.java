package dev.rtgum.host;

import android.content.Context;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Imports a Manager bundle into the calling app's private storage. */
public final class ModuleBundle implements Closeable {
    private static final long MAX_MODULE_BYTES = 32L * 1024L * 1024L;
    private static final long MAX_SCRIPT_BYTES = 256L * 1024L;
    private static final long MAX_TOTAL_BYTES = 100L * 1024L * 1024L;

    public static final class Selection {
        public final String packageName;
        public final String modulePath;
        public final String scriptPath;
        public final boolean enabled;
        public final boolean artHookEnabled;
        public final boolean memoryAccessEnabled;
        public final boolean antiDebugEnabled;

        private Selection(String packageName, String modulePath,
                          String scriptPath, boolean enabled,
                          boolean artHookEnabled,
                          boolean memoryAccessEnabled,
                          boolean antiDebugEnabled) {
            this.packageName = packageName;
            this.modulePath = modulePath;
            this.scriptPath = scriptPath;
            this.enabled = enabled;
            this.artHookEnabled = artHookEnabled;
            this.memoryAccessEnabled = memoryAccessEnabled;
            this.antiDebugEnabled = antiDebugEnabled;
        }
    }

    private final File directory;
    private final List<Selection> selections;
    private boolean closed;

    private ModuleBundle(File directory, List<Selection> selections) {
        this.directory = directory;
        this.selections = Collections.unmodifiableList(selections);
    }

    public List<Selection> selections() {
        return selections;
    }

    /** Matches the exact package supplied by the embedding app. */
    public Selection forPackage(String packageName) {
        for (Selection selection : selections) {
            if (selection.enabled && selection.packageName.equals(packageName)) return selection;
        }
        return null;
    }

    public static ModuleBundle importFrom(Context context, Uri uri) throws Exception {
        if (context == null || uri == null) throw new IllegalArgumentException("context and URI required");
        File parent = new File(context.getFilesDir(), "rtgum-bundles");
        if (!parent.isDirectory() && !parent.mkdirs())
            throw new IllegalStateException("cannot create bundle directory");
        File directory = new File(parent, UUID.randomUUID().toString());
        if (!directory.mkdir()) throw new IllegalStateException("cannot create import directory");
        try {
            extract(context, uri, directory);
            List<Selection> selections = readManifest(directory);
            return new ModuleBundle(directory, selections);
        } catch (Exception error) {
            deleteTree(directory);
            throw error;
        }
    }

    private static void extract(Context context, Uri uri, File directory) throws Exception {
        InputStream source = context.getContentResolver().openInputStream(uri);
        if (source == null) throw new IllegalArgumentException("cannot open bundle");
        HashSet<String> names = new HashSet<>();
        int entries = 0;
        long total = 0;
        try (ZipInputStream zip = new ZipInputStream(source)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName();
                if (++entries > 201 || !validEntryName(name) || entry.isDirectory() ||
                        !names.add(name)) {
                    throw new IllegalArgumentException("invalid bundle entry");
                }
                File file = new File(directory, name);
                File folder = file.getParentFile();
                if (!folder.isDirectory() && !folder.mkdirs())
                    throw new IllegalStateException("cannot create bundle path");
                long limit = name.endsWith(".lua") ? MAX_SCRIPT_BYTES :
                        "manifest.json".equals(name) ? 1024L * 1024L : MAX_MODULE_BYTES;
                long size = 0;
                try (OutputStream output = new FileOutputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int count;
                    while ((count = zip.read(buffer)) != -1) {
                        size += count;
                        total += count;
                        if (size > limit || total > MAX_TOTAL_BYTES)
                            throw new IllegalArgumentException("bundle size limit exceeded");
                        output.write(buffer, 0, count);
                    }
                }
                zip.closeEntry();
            }
        }
    }

    private static List<Selection> readManifest(File directory) throws Exception {
        File manifestFile = new File(directory, "manifest.json");
        if (!manifestFile.isFile() || manifestFile.length() > 1024L * 1024L)
            throw new IllegalArgumentException("missing manifest");
        JSONObject manifest = new JSONObject(readText(manifestFile));
        if (!"rtgum-module-bundle".equals(manifest.getString("format")) ||
                manifest.getInt("version") != 1) {
            throw new IllegalArgumentException("unsupported bundle format");
        }
        JSONArray entries = manifest.getJSONArray("entries");
        if (entries.length() > 100) throw new IllegalArgumentException("too many modules");
        ArrayList<Selection> result = new ArrayList<>();
        HashSet<String> packages = new HashSet<>();
        for (int index = 0; index < entries.length(); ++index) {
            JSONObject item = entries.getJSONObject(index);
            String packageName = item.getString("package");
            String moduleName = item.getString("module");
            String moduleDigest = item.getString("sha256");
            String scriptName = item.optString("script", "");
            String scriptDigest = item.optString("script_sha256", "");
            if (!validPackage(packageName) || !packages.add(packageName) ||
                    !moduleName.matches("modules/[a-zA-Z0-9_-]+\\.ghm") ||
                    (!scriptName.isEmpty() &&
                            !scriptName.matches("scripts/[a-zA-Z0-9_-]+\\.lua"))) {
                throw new IllegalArgumentException("invalid module selection");
            }
            File module = new File(directory, moduleName);
            if (!module.isFile() || !arm64Elf(module) ||
                    !moduleDigest.equals(sha256(module))) {
                throw new IllegalArgumentException("module integrity check failed");
            }
            String scriptPath = "";
            if (!scriptName.isEmpty()) {
                File script = new File(directory, scriptName);
                if (!script.isFile() || !scriptDigest.equals(sha256(script)))
                    throw new IllegalArgumentException("script integrity check failed");
                scriptPath = script.getAbsolutePath();
            } else if (!scriptDigest.isEmpty()) {
                throw new IllegalArgumentException("invalid script digest");
            }
            result.add(new Selection(packageName, module.getAbsolutePath(), scriptPath,
                    item.getBoolean("enabled"), item.optBoolean("art_hook", false),
                    item.optBoolean("memory_access", false),
                    item.optBoolean("anti_debug", false)));
        }
        return result;
    }

    private static boolean validPackage(String name) {
        return name != null && name.length() <= 255 &&
                name.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+");
    }

    private static boolean validEntryName(String name) {
        return "manifest.json".equals(name) ||
                name.matches("(modules/[a-zA-Z0-9_-]+\\.ghm|scripts/[a-zA-Z0-9_-]+\\.lua)");
    }

    private static boolean arm64Elf(File file) throws Exception {
        byte[] header = new byte[20];
        try (InputStream input = new FileInputStream(file)) {
            int offset = 0;
            while (offset < header.length) {
                int count = input.read(header, offset, header.length - offset);
                if (count < 0) return false;
                offset += count;
            }
        }
        return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' &&
                header[3] == 'F' && header[4] == 2 && header[5] == 1 &&
                header[16] == 3 && header[17] == 0 &&
                (header[18] & 0xff) == 183 && header[19] == 0;
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        StringBuilder result = new StringBuilder(64);
        for (byte value : digest.digest()) result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return result.toString();
    }

    private static String readText(File file) throws Exception {
        try (InputStream input = new FileInputStream(file);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 1024 * 1024)
                    throw new IllegalArgumentException("manifest is too large");
                output.write(buffer, 0, count);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    /** Call only after the embedding app has unloaded every module in this bundle. */
    @Override
    public void close() {
        if (closed) return;
        closed = true;
        deleteTree(directory);
    }

    private static void deleteTree(File file) {
        File[] children = file.listFiles();
        if (children != null) for (File child : children) deleteTree(child);
        file.delete();
    }
}
