'use strict';

const kExpectedAccessFlags = 0x119;
const kRelevantAccessFlagsMask = 0xafcfffff;
const kReturnValue = 0x12345678;
const kFlagsToClear = 0x48100010;
const kCompileDontBother = 0x02000000;

function requireSymbol(module, name) {
  const symbol = module.enumerateSymbols().find(candidate =>
    candidate.name === name);
  if (symbol === undefined) {
    throw new Error(`missing ART symbol: ${name}`);
  }
  return symbol.address;
}

function readMessage(buffer) {
  return buffer.readUtf8String() || '';
}

Java.performNow(() => {
  const runtime = Process.getModuleByName('libandroid_runtime.so');
  const art = Process.getModuleByName('libart.so');
  const testModule = Module.load(
      '/data/local/tmp/libart-hook-live-test.so');
  const suspendAll = requireSymbol(
      art, '_ZN3art10ThreadList10SuspendAllEPKcb');
  const resumeAll = requireSymbol(
      art, '_ZN3art10ThreadList9ResumeAllEv');

  const create = new NativeFunction(
      testModule.getExportByName('art_hook_live_create'), 'pointer',
      ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'int', 'pointer',
        'pointer', 'pointer', 'uint64', 'pointer', 'ulong']);
  const activate = new NativeFunction(
      testModule.getExportByName('art_hook_live_activate'), 'int',
      ['pointer', 'pointer', 'ulong']);
  const deactivate = new NativeFunction(
      testModule.getExportByName('art_hook_live_deactivate'), 'int',
      ['pointer', 'pointer', 'ulong']);
  const destroy = new NativeFunction(
      testModule.getExportByName('art_hook_live_destroy'), 'void',
      ['pointer']);
  const enterCount = new NativeFunction(
      testModule.getExportByName('art_hook_live_enter_count'), 'uint64',
      ['pointer']);
  const leaveCount = new NativeFunction(
      testModule.getExportByName('art_hook_live_leave_count'), 'uint64',
      ['pointer']);
  const flagsCycle = new NativeFunction(
      testModule.getExportByName('art_hook_live_flags_cycle'), 'int',
      ['pointer', 'uint', 'uint', 'pointer', 'pointer', 'pointer',
        'pointer', 'ulong']);

  const ProcessClass = Java.use('android.os.Process');
  const method = ProcessClass.getElapsedCpuTime.overload();
  const apiLevel = Java.use('android.os.Build$VERSION').SDK_INT.value;
  const error = Memory.alloc(512);
  error.writeUtf8String('');

  const before = ProcessClass.getElapsedCpuTime().toString();
  const handle = create(
      method.handle, runtime.base, runtime.base.add(runtime.size),
      kExpectedAccessFlags, kRelevantAccessFlagsMask, apiLevel,
      Java.api.artThreadList, suspendAll, resumeAll, kReturnValue,
      error, 512);
  if (handle.isNull()) {
    throw new Error(`create failed: ${readMessage(error)}`);
  }

  let active = false;
  try {
    const beforeFlags = Memory.alloc(4);
    const duringFlags = Memory.alloc(4);
    const afterFlags = Memory.alloc(4);
    error.writeUtf8String('');
    const flagsResult = flagsCycle(
        handle, kFlagsToClear, kCompileDontBother, beforeFlags,
        duringFlags, afterFlags, error, 512);
    if (flagsResult !== 0) {
      throw new Error(`flags cycle failed: ${readMessage(error)}`);
    }
    const beforeFlagsValue = beforeFlags.readU32();
    const duringFlagsValue = duringFlags.readU32();
    const afterFlagsValue = afterFlags.readU32();
    const expectedDuring =
        ((beforeFlagsValue & ~kFlagsToClear) | kCompileDontBother) >>> 0;
    if (duringFlagsValue !== expectedDuring ||
        afterFlagsValue !== beforeFlagsValue) {
      throw new Error(
          `flags mismatch: before=0x${beforeFlagsValue.toString(16)} ` +
          `during=0x${duringFlagsValue.toString(16)} ` +
          `after=0x${afterFlagsValue.toString(16)}`);
    }
    console.log(
        `FLAGS_TEST_PASS before=0x${beforeFlagsValue.toString(16)} ` +
        `during=0x${duringFlagsValue.toString(16)} ` +
        `after=0x${afterFlagsValue.toString(16)}`);

    let hooked = '';
    let restored = '';
    for (let iteration = 0; iteration !== 10; iteration++) {
      error.writeUtf8String('');
      const activateResult = activate(handle, error, 512);
      if (activateResult !== 0) {
        throw new Error(
            `activate ${iteration} failed: ${readMessage(error)}`);
      }
      active = true;

      hooked = ProcessClass.getElapsedCpuTime().toString();
      if (hooked !== kReturnValue.toString()) {
        throw new Error(
            `hooked call ${iteration} returned ${hooked}, ` +
            `expected ${kReturnValue}`);
      }

      error.writeUtf8String('');
      const deactivateResult = deactivate(handle, error, 512);
      if (deactivateResult !== 0) {
        throw new Error(
            `deactivate ${iteration} failed: ${readMessage(error)}`);
      }
      active = false;

      restored = ProcessClass.getElapsedCpuTime().toString();
      if (restored === kReturnValue.toString()) {
        throw new Error(
            `restored call ${iteration} still reaches the trampoline`);
      }
    }
    const enters = enterCount(handle).toString();
    const leaves = leaveCount(handle).toString();
    if (enters !== '10' || leaves !== '10') {
      throw new Error(
          `callback counts differ: enter=${enters} leave=${leaves}`);
    }
    console.log(
        `LIVE_TEST_PASS cycles=10 before=${before} ` +
        `hooked=${hooked} restored=${restored} ` +
        `enter=${enters} leave=${leaves}`);
  } finally {
    if (active) {
      error.writeUtf8String('');
      const result = deactivate(handle, error, 512);
      console.log(
          `cleanup deactivate=${result} message=${readMessage(error)}`);
    }
    destroy(handle);
  }
});
