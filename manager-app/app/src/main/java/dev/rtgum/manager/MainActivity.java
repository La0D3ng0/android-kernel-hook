package dev.rtgum.manager;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import dev.rtgum.host.ModuleBundle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Locale;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class MainActivity extends Activity {
    private static final int PICK_MODULE = 1;
    private static final int EXPORT_BUNDLE = 2;
    private static final int IMPORT_BUNDLE = 3;
    private static final long MAX_MODULE_BYTES = 32L * 1024L * 1024L;
    private static final String STATE_PREFERENCES = "manager_state";
    private static final String STATE_RECORDS = "records";
    private static final String STATE_SCHEMA = "schema_version";
    private static final int CURRENT_STATE_SCHEMA = 2;
    private static final String AUTOMATION_PREFIX = "rtgum:";
    private static final String[] SAMPLE_PACKAGES = {
            "com.imusic.iting", "com.threegene.yeemiao", "com.funshion.video.mobile"
    };
    private static final boolean NATIVE_READY;
    private static final String NATIVE_LOAD_ERROR;

    static {
        boolean loaded = false;
        String loadError = null;
        try {
            System.loadLibrary("rtgum_manager");
            loaded = true;
        } catch (Throwable error) {
            loadError = error.getClass().getSimpleName() + ": " + error.getMessage();
        }
        NATIVE_READY = loaded;
        NATIVE_LOAD_ERROR = loadError;
    }

    private static native String nativeEnroll();
    private static native String nativeControl(String session, String command);

    private final ArrayList<Record> records = new ArrayList<>();
    private AutoCompleteTextView packageInput;
    private EditText scriptInput;
    private TextView selectedModuleLabel;
    private CheckBox artHookInput;
    private CheckBox memoryAccessInput;
    private CheckBox antiDebugInput;
    private LinearLayout recordList;
    private TextView kernelStatus;
    private TextView permissionStatus;
    private TextView operationStatus;
    private TextView stateStatus;
    private Uri selectedModuleUri;
    private final Object kernelSyncLock = new Object();
    private ArrayList<RecordSnapshot> pendingKernelSnapshot;
    private boolean kernelSyncRunning;
    private String kernelSession;

    private static final class Record {
        String id;
        String packageName;
        String sha256;
        boolean enabled;
        boolean artHookEnabled;
        boolean memoryAccessEnabled;
        boolean antiDebugEnabled;

        JSONObject toJson() throws Exception {
            JSONObject object = new JSONObject();
            object.put("id", id);
            object.put("package", packageName);
            object.put("sha256", sha256);
            object.put("enabled", enabled);
            object.put("art_hook", artHookEnabled);
            object.put("memory_access", memoryAccessEnabled);
            object.put("anti_debug", antiDebugEnabled);
            return object;
        }
    }

    private static final class RecordSnapshot {
        String id;
        String packageName;
        String sha256;
        boolean enabled;
        boolean artHookEnabled;
        boolean memoryAccessEnabled;
        boolean antiDebugEnabled;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        migrateLegacyState();
        loadRecords();
        buildUi();
        renderRecords();
        requestKernelSync();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            root.setPadding(pad, pad + insets.getSystemWindowInsetTop(), pad,
                    pad + insets.getSystemWindowInsetBottom());
            return insets;
        });
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("android-kernel-hook 模块管理");
        title.setTextSize(22);
        identify(title, "title");
        root.addView(title);

        TextView description = new TextView(this);
        description.setText("选择本地 .ghm、精确指定包名，并离线导出模块包。"
                + "运行时由目标应用主动导入。\n");
        identify(description, "description");
        root.addView(description);

        TextView filePermission = new TextView(this);
        filePermission.setText("文件访问：使用 Android 系统文件选择器，无需存储权限或“所有文件访问”权限。");
        identify(filePermission, "file-permission-status");
        root.addView(filePermission, wide());

        permissionStatus = new TextView(this);
        identify(permissionStatus, NATIVE_READY
                ? "permission-status-checking" : "permission-status-blocked");
        permissionStatus.setText(NATIVE_READY
                ? "KPM 管理权限：正在检查"
                : "KPM 管理权限：本机桥未加载，请重新安装完整 Manager APK。");
        root.addView(permissionStatus, wide());

        kernelStatus = new TextView(this);
        identify(kernelStatus, "kernel-status");
        kernelStatus.setText(NATIVE_READY ? "内核连接：正在认证"
                : "内核连接：本机桥未加载（" + NATIVE_LOAD_ERROR + "）");
        root.addView(kernelStatus, wide());

        Button sync = new Button(this);
        sync.setText("重新检查权限并同步配置");
        identify(sync, "permission-retry");
        sync.setEnabled(NATIVE_READY);
        sync.setOnClickListener(view -> requestKernelSync());
        root.addView(sync, wide());

        packageInput = new AutoCompleteTextView(this);
        packageInput.setHint("应用包名，例如 com.example.app");
        packageInput.setSingleLine(true);
        identify(packageInput, "package-input");
        packageInput.setAdapter(new ArrayAdapter<>(this,
                android.R.layout.simple_dropdown_item_1line, SAMPLE_PACKAGES));
        root.addView(packageInput, wide());

        Spinner samples = new Spinner(this);
        String[] choices = {"选择测试包（可选）", SAMPLE_PACKAGES[0], SAMPLE_PACKAGES[1],
                SAMPLE_PACKAGES[2]};
        samples.setAdapter(new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, choices));
        identify(samples, "sample-packages");
        samples.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position > 0) packageInput.setText(choices[position], false);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
        root.addView(samples, wide());

        Button pick = new Button(this);
        pick.setText("选择 .ghm 文件");
        identify(pick, "pick-module");
        pick.setOnClickListener(view -> openDocument(PICK_MODULE, "application/octet-stream"));
        root.addView(pick, wide());

        selectedModuleLabel = new TextView(this);
        selectedModuleLabel.setText("尚未选择模块");
        identify(selectedModuleLabel, "selected-module");
        root.addView(selectedModuleLabel);

        artHookInput = new CheckBox(this);
        artHookInput.setText("启用 ART Java 方法 Hook（按需加载 mako）");
        artHookInput.setChecked(false);
        identify(artHookInput, "new-art-hook");
        root.addView(artHookInput, wide());

        memoryAccessInput = new CheckBox(this);
        memoryAccessInput.setText("允许实验性跨进程内存读写（仅此包）");
        memoryAccessInput.setChecked(false);
        identify(memoryAccessInput, "new-memory-access");
        root.addView(memoryAccessInput, wide());

        antiDebugInput = new CheckBox(this);
        antiDebugInput.setText("启用内核 HWBP 反调试假账本（仅此包）");
        antiDebugInput.setChecked(false);
        identify(antiDebugInput, "new-anti-debug");
        root.addView(antiDebugInput, wide());

        scriptInput = new EditText(this);
        scriptInput.setHint("可选 Lua 脚本（与模块一同导出）");
        scriptInput.setMinLines(4);
        scriptInput.setMaxLines(12);
        identify(scriptInput, "script-input");
        root.addView(scriptInput, wide());

        Button save = new Button(this);
        save.setText("添加或替换配置");
        identify(save, "save-config");
        save.setOnClickListener(view -> saveSelection());
        root.addView(save, wide());

        Button export = new Button(this);
        export.setText("导出离线模块包");
        identify(export, "export-bundle");
        export.setOnClickListener(view -> createBundle());
        root.addView(export, wide());

        Button importButton = new Button(this);
        importButton.setText("导入离线模块包");
        identify(importButton, "import-bundle");
        importButton.setOnClickListener(view -> openDocument(IMPORT_BUNDLE, "application/zip"));
        root.addView(importButton, wide());

        operationStatus = new TextView(this);
        operationStatus.setText("操作状态：就绪");
        identify(operationStatus, "operation-status");
        root.addView(operationStatus, wide());

        stateStatus = new TextView(this);
        identify(stateStatus, "state-status");
        root.addView(stateStatus, wide());

        recordList = new LinearLayout(this);
        recordList.setOrientation(LinearLayout.VERTICAL);
        identify(recordList, "record-list");
        root.addView(recordList, wide());
        setContentView(scroll);
    }

    private static <T extends View> T identify(T view, String name) {
        view.setContentDescription(AUTOMATION_PREFIX + name);
        return view;
    }

    private LinearLayout.LayoutParams wide() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void openDocument(int request, String mime) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType(mime);
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{mime, "*/*"});
        startActivityForResult(intent, request);
    }

    private void createBundle() {
        if (records.isEmpty()) {
            show("没有可导出的配置");
            return;
        }
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/zip");
        intent.putExtra(Intent.EXTRA_TITLE, "rtgum-modules.zip");
        startActivityForResult(intent, EXPORT_BUNDLE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        try {
            if (requestCode == PICK_MODULE) {
                selectedModuleUri = uri;
                selectedModuleLabel.setText("已选择：" + displayName(uri));
            } else if (requestCode == EXPORT_BUNDLE) {
                exportBundle(uri);
                show("模块包已导出");
            } else if (requestCode == IMPORT_BUNDLE) {
                importBundle(uri);
                show("模块包已导入");
            }
        } catch (Exception error) {
            show("操作失败：" + error.getMessage());
        }
    }

    private String displayName(Uri uri) {
        String name = null;
        try (Cursor cursor = getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (column >= 0) name = cursor.getString(column);
            }
        } catch (Exception ignored) {
            // Some document providers do not implement metadata queries.
        }
        if (name == null || name.trim().isEmpty()) name = uri.getLastPathSegment();
        if (name == null || name.trim().isEmpty()) name = "未命名文档";
        name = name.replace('\n', ' ').replace('\r', ' ').trim();
        return name.length() <= 255 ? name : name.substring(0, 255);
    }

    private static boolean validPackage(String name) {
        return name != null && name.length() <= 255 &&
                name.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+");
    }

    private File moduleFile(String id) {
        return new File(new File(getFilesDir(), "modules"), id + ".ghm");
    }

    private File scriptFile(String id) {
        return new File(new File(getFilesDir(), "scripts"), id + ".lua");
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

    private static void copyLimited(InputStream input, OutputStream output, long maximum)
            throws Exception {
        byte[] buffer = new byte[8192];
        long total = 0;
        int count;
        while ((count = input.read(buffer)) != -1) {
            total += count;
            if (total > maximum) throw new IllegalArgumentException("文件过大");
            output.write(buffer, 0, count);
        }
    }

    private static boolean isArm64SharedObject(File file) throws Exception {
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

    private void saveSelection() {
        String packageName = packageInput.getText().toString().trim();
        if (!validPackage(packageName) || selectedModuleUri == null) {
            show("请输入有效包名并选择 .ghm 文件");
            return;
        }
        String script = scriptInput.getText().toString();
        if (script.getBytes(StandardCharsets.UTF_8).length > 256 * 1024) {
            show("Lua 脚本不能超过 256 KiB");
            return;
        }
        Record replacement = new Record();
        replacement.id = UUID.randomUUID().toString();
        replacement.packageName = packageName;
        replacement.enabled = true;
        replacement.artHookEnabled = artHookInput.isChecked();
        replacement.memoryAccessEnabled = memoryAccessInput.isChecked();
        replacement.antiDebugEnabled = antiDebugInput.isChecked();
        File module = moduleFile(replacement.id);
        File lua = scriptFile(replacement.id);
        try {
            if (!module.getParentFile().mkdirs() && !module.getParentFile().isDirectory())
                throw new IllegalStateException("无法创建模块目录");
            try (InputStream input = getContentResolver().openInputStream(selectedModuleUri);
                 OutputStream output = new FileOutputStream(module)) {
                if (input == null) throw new IllegalArgumentException("无法读取模块文件");
                copyLimited(input, output, MAX_MODULE_BYTES);
            }
            if (!isArm64SharedObject(module))
                throw new IllegalArgumentException("模块不是 ARM64 ELF 共享对象");
            replacement.sha256 = sha256(module);
            if (!script.isEmpty()) {
                if (!lua.getParentFile().mkdirs() && !lua.getParentFile().isDirectory())
                    throw new IllegalStateException("无法创建脚本目录");
                try (OutputStream output = new FileOutputStream(lua)) {
                    output.write(script.getBytes(StandardCharsets.UTF_8));
                }
            }
            Record previous = null;
            int previousIndex = -1;
            for (int index = records.size() - 1; index >= 0; --index) {
                if (records.get(index).packageName.equals(packageName)) {
                    previous = records.remove(index);
                    previousIndex = index;
                }
            }
            records.add(replacement);
            if (!persistRecords()) {
                records.remove(replacement);
                if (previous != null) records.add(previousIndex, previous);
                throw new IllegalStateException("无法持久化配置");
            }
            if (previous != null) {
                moduleFile(previous.id).delete();
                scriptFile(previous.id).delete();
            }
            selectedModuleUri = null;
            selectedModuleLabel.setText("尚未选择模块");
            artHookInput.setChecked(false);
            memoryAccessInput.setChecked(false);
            antiDebugInput.setChecked(false);
            scriptInput.setText("");
            renderRecords();
            show("配置已保存");
            requestKernelSync();
        } catch (Exception error) {
            module.delete();
            lua.delete();
            show("保存失败：" + error.getMessage());
        }
    }

    private void renderRecords() {
        recordList.removeAllViews();
        if (stateStatus != null) {
            stateStatus.setText("配置存储：schema v" + CURRENT_STATE_SCHEMA + "，"
                    + records.size() + " 条");
        }
        TextView heading = new TextView(this);
        heading.setText("\n当前配置（精确包名）");
        heading.setTextSize(18);
        identify(heading, "record-heading");
        recordList.addView(heading);
        for (Record record : new ArrayList<>(records)) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, dp(8), 0, dp(8));
            identify(row, "record:" + record.packageName);
            TextView details = new TextView(this);
            details.setText(record.packageName + "\nSHA-256: " + record.sha256);
            identify(details, "record:" + record.packageName + ":details");
            row.addView(details);
            CheckBox enabled = new CheckBox(this);
            enabled.setText("启用");
            enabled.setChecked(record.enabled);
            identify(enabled, "record:" + record.packageName + ":enabled");
            enabled.setOnCheckedChangeListener((button, checked) -> {
                record.enabled = checked;
                if (!persistRecords()) {
                    show("启用状态保存失败");
                } else {
                    requestKernelSync();
                }
            });
            row.addView(enabled);
            CheckBox artHook = new CheckBox(this);
            artHook.setText("ART Java 方法 Hook");
            artHook.setChecked(record.artHookEnabled);
            identify(artHook, "record:" + record.packageName + ":art-hook");
            artHook.setOnCheckedChangeListener((button, checked) -> {
                record.artHookEnabled = checked;
                if (!persistRecords()) {
                    show("ART Hook 状态保存失败");
                } else {
                    requestKernelSync();
                }
            });
            row.addView(artHook);
            CheckBox memoryAccess = new CheckBox(this);
            memoryAccess.setText("实验性跨进程内存读写白名单");
            memoryAccess.setChecked(record.memoryAccessEnabled);
            identify(memoryAccess, "record:" + record.packageName + ":memory-access");
            memoryAccess.setOnCheckedChangeListener((button, checked) -> {
                record.memoryAccessEnabled = checked;
                if (!persistRecords()) {
                    show("内存读写白名单状态保存失败");
                } else {
                    requestKernelSync();
                }
            });
            row.addView(memoryAccess);
            CheckBox antiDebug = new CheckBox(this);
            antiDebug.setText("HWBP 反调试假账本");
            antiDebug.setChecked(record.antiDebugEnabled);
            identify(antiDebug, "record:" + record.packageName + ":anti-debug");
            antiDebug.setOnCheckedChangeListener((button, checked) -> {
                record.antiDebugEnabled = checked;
                if (!persistRecords()) {
                    show("反调试状态保存失败");
                } else {
                    requestKernelSync();
                }
            });
            row.addView(antiDebug);
            Button remove = new Button(this);
            remove.setText("删除");
            identify(remove, "record:" + record.packageName + ":delete");
            remove.setOnClickListener(view -> {
                records.remove(record);
                if (!persistRecords()) {
                    records.add(record);
                    show("删除操作未保存");
                    renderRecords();
                    return;
                }
                moduleFile(record.id).delete();
                scriptFile(record.id).delete();
                renderRecords();
                requestKernelSync();
            });
            row.addView(remove);
            recordList.addView(row, wide());
        }
    }

    private boolean persistRecords() {
        try {
            JSONArray array = new JSONArray();
            for (Record record : records) array.put(record.toJson());
            return getSharedPreferences(STATE_PREFERENCES, MODE_PRIVATE).edit()
                    .putInt(STATE_SCHEMA, CURRENT_STATE_SCHEMA)
                    .putString(STATE_RECORDS, array.toString()).commit();
        } catch (Exception error) {
            show("配置保存失败：" + error.getMessage());
            return false;
        }
    }

    private void loadRecords() {
        try {
            SharedPreferences state = getSharedPreferences(STATE_PREFERENCES, MODE_PRIVATE);
            JSONArray array = new JSONArray(state.getString(STATE_RECORDS, "[]"));
            for (int index = 0; index < array.length(); ++index) {
                JSONObject object = array.getJSONObject(index);
                Record record = new Record();
                record.id = object.getString("id");
                record.packageName = object.getString("package");
                record.sha256 = object.getString("sha256");
                record.enabled = object.getBoolean("enabled");
                record.artHookEnabled = object.optBoolean("art_hook", false);
                record.memoryAccessEnabled = object.optBoolean("memory_access", false);
                record.antiDebugEnabled = object.optBoolean("anti_debug", false);
                if (validPackage(record.packageName) && validId(record.id) &&
                        moduleFile(record.id).isFile()) records.add(record);
            }
        } catch (Exception error) {
            records.clear();
        }
    }

    private void migrateLegacyState() {
        SharedPreferences state = getSharedPreferences(STATE_PREFERENCES, MODE_PRIVATE);
        if (state.contains(STATE_RECORDS)) {
            if (state.getInt(STATE_SCHEMA, 0) < CURRENT_STATE_SCHEMA) {
                state.edit().putInt(STATE_SCHEMA, CURRENT_STATE_SCHEMA).commit();
            }
            return;
        }
        SharedPreferences legacy = getPreferences(MODE_PRIVATE);
        String records = legacy.getString(STATE_RECORDS, null);
        SharedPreferences.Editor editor = state.edit()
                .putInt(STATE_SCHEMA, CURRENT_STATE_SCHEMA);
        if (records != null) editor.putString(STATE_RECORDS, records);
        editor.commit();
    }

    private static void zipFile(ZipOutputStream zip, String name, File file) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        try (InputStream input = new FileInputStream(file)) {
            copyLimited(input, zip, MAX_MODULE_BYTES);
        }
        zip.closeEntry();
    }

    private void exportBundle(Uri uri) throws Exception {
        JSONObject manifest = new JSONObject();
        manifest.put("format", "rtgum-module-bundle");
        manifest.put("version", 1);
        JSONArray entries = new JSONArray();
        OutputStream destination = getContentResolver().openOutputStream(uri);
        if (destination == null) throw new IllegalArgumentException("无法写入目标文件");
        try (ZipOutputStream zip = new ZipOutputStream(destination)) {
            for (Record record : records) {
                File module = moduleFile(record.id);
                if (!module.isFile() || !record.sha256.equals(sha256(module)))
                    throw new IllegalStateException("模块文件已变化：" + record.packageName);
                String moduleName = "modules/" + record.id + ".ghm";
                String scriptName = "";
                File script = scriptFile(record.id);
                if (script.isFile()) scriptName = "scripts/" + record.id + ".lua";
                JSONObject entry = new JSONObject();
                entry.put("package", record.packageName);
                entry.put("module", moduleName);
                entry.put("sha256", record.sha256);
                entry.put("script", scriptName);
                entry.put("script_sha256", scriptName.isEmpty() ? "" : sha256(script));
                entry.put("enabled", record.enabled);
                entry.put("art_hook", record.artHookEnabled);
                entry.put("memory_access", record.memoryAccessEnabled);
                entry.put("anti_debug", record.antiDebugEnabled);
                entries.put(entry);
                zipFile(zip, moduleName, module);
                if (!scriptName.isEmpty()) zipFile(zip, scriptName, script);
            }
            manifest.put("entries", entries);
            zip.putNextEntry(new ZipEntry("manifest.json"));
            zip.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
    }

    private void importBundle(Uri uri) throws Exception {
        ArrayList<File> created = new ArrayList<>();
        boolean committed = false;
        try {
            ArrayList<Record> imported = new ArrayList<>();
            try (ModuleBundle bundle = ModuleBundle.importFrom(this, uri)) {
                for (ModuleBundle.Selection selection : bundle.selections()) {
                    Record record = new Record();
                    record.id = UUID.randomUUID().toString();
                    record.packageName = selection.packageName;
                    record.sha256 = sha256(new File(selection.modulePath));
                    record.enabled = selection.enabled;
                    record.artHookEnabled = selection.artHookEnabled;
                    record.memoryAccessEnabled = selection.memoryAccessEnabled;
                    record.antiDebugEnabled = selection.antiDebugEnabled;
                    created.add(moduleFile(record.id));
                    copyFile(new File(selection.modulePath), moduleFile(record.id));
                    if (!selection.scriptPath.isEmpty()) {
                        created.add(scriptFile(record.id));
                        copyFile(new File(selection.scriptPath), scriptFile(record.id));
                    }
                    imported.add(record);
                }
            }
            ArrayList<Record> previous = new ArrayList<>(records);
            records.clear();
            records.addAll(imported);
            if (!persistRecords()) {
                records.clear();
                records.addAll(previous);
                throw new IllegalStateException("无法保存导入配置");
            }
            committed = true;
            for (Record old : previous) {
                moduleFile(old.id).delete();
                scriptFile(old.id).delete();
            }
            renderRecords();
            requestKernelSync();
        } finally {
            if (!committed) for (File file : created) file.delete();
        }
    }

    private static boolean validId(String id) {
        try {
            return UUID.fromString(id).toString().equals(id);
        } catch (Exception error) {
            return false;
        }
    }

    private ArrayList<RecordSnapshot> snapshotRecords() {
        ArrayList<RecordSnapshot> snapshot = new ArrayList<>();
        for (Record record : records) {
            RecordSnapshot copy = new RecordSnapshot();
            copy.id = record.id;
            copy.packageName = record.packageName;
            copy.sha256 = record.sha256;
            copy.enabled = record.enabled;
            copy.artHookEnabled = record.artHookEnabled;
            copy.memoryAccessEnabled = record.memoryAccessEnabled;
            copy.antiDebugEnabled = record.antiDebugEnabled;
            snapshot.add(copy);
        }
        return snapshot;
    }

    private static String sessionFrom(String response) {
        if (response == null || !response.startsWith("ok ")) return null;
        int begin = response.indexOf("session=");
        if (begin < 0) return null;
        begin += "session=".length();
        if (begin + 64 > response.length()) return null;
        String value = response.substring(begin, begin + 64);
        return value.matches("[0-9a-fA-F]{64}") ? value : null;
    }

    private File ensureMakoRuntime() throws Exception {
        File source = new File(getApplicationInfo().nativeLibraryDir, "libmako-ghost.so");
        if (!source.isFile()) throw new IllegalStateException("APK 中缺少 mako 运行库");
        File target = new File(new File(getFilesDir(), "runtime"), "libmako-ghost.so");
        if (!target.isFile() || target.length() != source.length() ||
                !sha256(target).equals(sha256(source))) copyFile(source, target);
        return target;
    }

    private String clearKernelConfig() throws InterruptedException {
        String response = null;
        for (int attempt = 0; attempt < 40; ++attempt) {
            response = nativeControl(kernelSession, "daemon-config-clear 1");
            if (response != null && response.startsWith("ok ")) return response;
            if (response == null || (!response.contains("code=-16")
                    && !response.contains("retry=1"))) return response;
            Thread.sleep(50L);
        }
        return response;
    }

    private String syncKernel(ArrayList<RecordSnapshot> snapshot) {
        if (!NATIVE_READY) return "本机桥未加载（" + NATIVE_LOAD_ERROR + "）";
        try {
            /* Validate every local input before replacing the live KPM table.
             * This keeps a bad later record from leaving an earlier record
             * partially committed after the old table has been cleared. */
            File mako = null;
            for (RecordSnapshot record : snapshot) {
                if (!record.enabled) continue;
                File module = moduleFile(record.id);
                if (!module.isFile() || !record.sha256.equals(sha256(module)))
                    return "模块校验失败：" + record.packageName;
                if (record.artHookEnabled && mako == null) mako = ensureMakoRuntime();
            }
            if (kernelSession == null) {
                String enrollment = nativeEnroll();
                kernelSession = sessionFrom(enrollment);
                if (kernelSession == null) return "认证失败：" + enrollment;
            }
            String clear = clearKernelConfig();
            if (clear == null || !clear.startsWith("ok ")) {
                kernelSession = null;
                return "清理旧配置失败：" + clear;
            }
            String antiReset = nativeControl(kernelSession, "unhook-antidbg");
            if (antiReset == null || !antiReset.startsWith("ok ")) {
                kernelSession = null;
                return "清理旧反调试状态失败：" + antiReset;
            }
            int applied = 0;
            String lastApplied = null;
            boolean anyAntiDebug = false;
            for (RecordSnapshot record : snapshot) {
                if (!record.enabled) continue;
                File module = moduleFile(record.id);
                StringBuilder command = new StringBuilder("daemon-config 1 ")
                        .append(record.packageName).append(' ')
                        .append(module.getAbsolutePath()).append(' ')
                        .append(record.artHookEnabled ? mako.getAbsolutePath() : "-")
                        .append(" - - ")
                        .append(record.memoryAccessEnabled ? "mem" : "-").append(' ')
                        .append(record.antiDebugEnabled ? "antidbg" : "-");
                String response = nativeControl(kernelSession, command.toString());
                if (response == null || !response.startsWith("ok ")) {
                    String rollback = clearKernelConfig();
                    nativeControl(kernelSession, "unhook-antidbg");
                    if (rollback == null || !rollback.startsWith("ok ")) kernelSession = null;
                    return "同步失败（" + record.packageName + "）：" + response
                            + "；回滚=" + rollback;
                }
                anyAntiDebug |= record.antiDebugEnabled;
                lastApplied = response;
                ++applied;
            }
            String antiState = antiReset;
            if (anyAntiDebug) {
                antiState = nativeControl(kernelSession, "hook-antidbg");
                if (antiState == null || !antiState.startsWith("ok ")) {
                    String rollback = clearKernelConfig();
                    nativeControl(kernelSession, "unhook-antidbg");
                    return "启用反调试失败：" + antiState + "；回滚=" + rollback;
                }
            }
            String active = lastApplied == null ? "无启用配置" : lastApplied;
            return "已连接 KPM，已同步 " + applied + " 条配置；配置=" + active
                    + "；反调试=" + antiState + "；清理=" + clear;
        } catch (Throwable error) {
            return "同步异常：" + error.getMessage();
        }
    }

    private void requestKernelSync() {
        if (!NATIVE_READY || kernelStatus == null) return;
        synchronized (kernelSyncLock) {
            pendingKernelSnapshot = snapshotRecords();
            if (kernelSyncRunning) return;
            kernelSyncRunning = true;
        }
        setConnectionState("checking", "KPM 管理权限：正在检查", "内核连接：正在同步");
        new Thread(() -> {
            while (true) {
                ArrayList<RecordSnapshot> snapshot;
                synchronized (kernelSyncLock) {
                    snapshot = pendingKernelSnapshot;
                    pendingKernelSnapshot = null;
                }
                String result = syncKernel(snapshot);
                runOnUiThread(() -> {
                    if (result != null && result.startsWith("已连接 KPM")) {
                        setConnectionState("granted",
                                "KPM 管理权限：已授权",
                                "内核连接：" + result);
                    } else {
                        setConnectionState("blocked",
                                "KPM 管理权限：未就绪。请确认 KernelPatch/KPM 已加载、"
                                        + "Manager 签名受信任，然后点击“重新检查权限并同步配置”。",
                                "内核连接：" + result);
                    }
                });
                synchronized (kernelSyncLock) {
                    if (pendingKernelSnapshot == null) {
                        kernelSyncRunning = false;
                        return;
                    }
                }
            }
        }, "rtgum-manager-sync").start();
    }

    private void setConnectionState(String state, String permission, String kernel) {
        if (permissionStatus != null) {
            permissionStatus.setText(permission);
            identify(permissionStatus, "permission-status-" + state);
        }
        if (kernelStatus != null) kernelStatus.setText(kernel);
    }


    private static void copyFile(File source, File target) throws Exception {
        if (!target.getParentFile().mkdirs() && !target.getParentFile().isDirectory())
            throw new IllegalStateException("无法创建目标目录");
        try (InputStream input = new FileInputStream(source);
             OutputStream output = new FileOutputStream(target)) {
            copyLimited(input, output, MAX_MODULE_BYTES);
        }
    }

    private void show(String message) {
        if (operationStatus != null) operationStatus.setText("操作状态：" + message);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}
