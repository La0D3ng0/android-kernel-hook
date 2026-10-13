'use strict';

// Frida hides its internal gum_interceptor_* C symbols from CModule. This
// test adapter therefore drives the same Gum backend through Interceptor and
// uses CModule only for a stable invocation-context ABI consumed by C++.
const contextSource = `
#include <stdint.h>

typedef struct {
  void *arguments[8];
  void *return_value;
  void *function;
  void *cpu_context;
  void *return_address;
  void *listener_function_data;
  void *replacement_data;
  uint64_t thread_id;
  uint32_t depth;
  uint32_t reserved;
} ArtHookInvocationContext;

static ArtHookInvocationContext *current_invocation;

void *get_nth_argument(void *raw, uint32_t index) {
  ArtHookInvocationContext *context = raw;
  return index < 8 ? context->arguments[index] : 0;
}

void replace_nth_argument(void *raw, uint32_t index, void *value) {
  ArtHookInvocationContext *context = raw;
  if (index < 8)
    context->arguments[index] = value;
}

void *get_return_value(void *raw) {
  return ((ArtHookInvocationContext *) raw)->return_value;
}

void replace_return_value(void *raw, void *value) {
  ((ArtHookInvocationContext *) raw)->return_value = value;
}

void *get_function(void *raw) {
  return ((ArtHookInvocationContext *) raw)->function;
}

void *get_cpu_context(void *raw) {
  return ((ArtHookInvocationContext *) raw)->cpu_context;
}

void *get_return_address(void *raw) {
  return ((ArtHookInvocationContext *) raw)->return_address;
}

uint64_t get_thread_id(void *raw) {
  return ((ArtHookInvocationContext *) raw)->thread_id;
}

uint32_t get_depth(void *raw) {
  return ((ArtHookInvocationContext *) raw)->depth;
}

void *get_listener_function_data(void *raw) {
  return ((ArtHookInvocationContext *) raw)->listener_function_data;
}

void *get_replacement_data(void *raw) {
  return ((ArtHookInvocationContext *) raw)->replacement_data;
}

void *get_current_invocation(void) {
  return current_invocation;
}

`;

const kContextSize = 128;
const kReturnValueOffset = 64;
const kFunctionOffset = 72;
const kCpuContextOffset = 80;
const kReturnAddressOffset = 88;
const kListenerDataOffset = 96;
const kReplacementDataOffset = 104;
const kThreadIdOffset = 112;
const kDepthOffset = 120;

function makeContext(args, target, invocation, listenerData) {
  const context = Memory.alloc(kContextSize);
  for (let index = 0; index !== 8; index++) {
    context.add(index * Process.pointerSize).writePointer(args[index]);
  }
  context.add(kReturnValueOffset).writePointer(NULL);
  context.add(kFunctionOffset).writePointer(target);
  context.add(kCpuContextOffset).writePointer(NULL);
  context.add(kReturnAddressOffset).writePointer(invocation.returnAddress);
  context.add(kListenerDataOffset).writePointer(listenerData);
  context.add(kReplacementDataOffset).writePointer(NULL);
  context.add(kThreadIdOffset).writeU64(invocation.threadId);
  context.add(kDepthOffset).writeU32(invocation.depth);
  return context;
}

function syncArguments(context, args) {
  for (let index = 0; index !== 8; index++) {
    args[index] = context.add(index * Process.pointerSize).readPointer();
  }
}

try {
  const testModule = Module.load(
      '/data/local/tmp/libart-hook-gum-live-test.so');
  const apiSize = new NativeFunction(
      testModule.getExportByName('art_hook_gum_live_api_size'), 'ulong', []);
  const run = new NativeFunction(
      testModule.getExportByName('art_hook_gum_live_run'), 'int',
      ['pointer', 'ulong', 'pointer', 'pointer', 'pointer', 'ulong']);
  const target = testModule.getExportByName('art_hook_gum_live_target');
  const replacement =
      testModule.getExportByName('art_hook_gum_live_replacement');

  const contextModule = new CModule(contextSource);
  let nextListenerId = 1;
  let transactionDepth = 0;
  const listeners = new Map();
  const replacements = new Map();
  const retiredReplacements = [];
  const retainedCallbacks = {};

  function listenerKey(handle) {
    return handle.toString();
  }

  function makeListener(onEnter, onLeave, data, destroy, probe) {
    const handle = ptr(0x10000 + nextListenerId++ * 16);
    listeners.set(listenerKey(handle), {
      handle,
      onEnter: onEnter.isNull()
        ? null
        : new NativeFunction(onEnter, 'void', ['pointer', 'pointer']),
      onLeave: onLeave.isNull()
        ? null
        : new NativeFunction(onLeave, 'void', ['pointer', 'pointer']),
      data,
      destroy: destroy.isNull()
        ? null
        : new NativeFunction(destroy, 'void', ['pointer']),
      probe,
      hook: null,
      listenerData: NULL
    });
    return handle;
  }

  retainedCallbacks.obtain = new NativeCallback(() => ptr(1), 'pointer', []);
  retainedCallbacks.objectUnref = new NativeCallback(object => {
    if (object.equals(ptr(1)))
      return;
    const key = listenerKey(object);
    const listener = listeners.get(key);
    if (listener === undefined)
      return;
    if (listener.destroy !== null)
      listener.destroy(listener.data);
    listeners.delete(key);
  }, 'void', ['pointer']);
  retainedCallbacks.makeCallListener = new NativeCallback(
      (onEnter, onLeave, data, destroy) =>
        makeListener(onEnter, onLeave, data, destroy, false),
      'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
  retainedCallbacks.makeProbeListener = new NativeCallback(
      (onHit, data, destroy) =>
        makeListener(onHit, NULL, data, destroy, true),
      'pointer', ['pointer', 'pointer', 'pointer']);
  retainedCallbacks.attach = new NativeCallback(
      (_interceptor, attachTarget, listenerHandle, listenerData) => {
        const listener = listeners.get(listenerKey(listenerHandle));
        if (listener === undefined || listener.hook !== null)
          return -2;
        listener.listenerData = listenerData;
        listener.hook = Interceptor.attach(attachTarget, {
          onEnter(args) {
            const context = makeContext(
                args, attachTarget, this, listener.listenerData);
            this.artHookContext = context;
            this.artHookArguments = args;
            if (listener.onEnter !== null)
              listener.onEnter(context, listener.data);
            syncArguments(context, args);
          },
          onLeave(retval) {
            if (listener.probe || listener.onLeave === null)
              return;
            const context = this.artHookContext;
            context.add(kReturnValueOffset).writePointer(retval);
            listener.onLeave(context, listener.data);
            retval.replace(
                context.add(kReturnValueOffset).readPointer());
          }
        });
        return 0;
      }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
  retainedCallbacks.detach = new NativeCallback(
      (_interceptor, listenerHandle) => {
        const listener = listeners.get(listenerKey(listenerHandle));
        if (listener !== undefined && listener.hook !== null) {
          listener.hook.detach();
          listener.hook = null;
        }
      }, 'void', ['pointer', 'pointer']);
  retainedCallbacks.replace = new NativeCallback(
      (_interceptor, replaceTarget, implementation, replacementData,
       originalOutput) => {
        const nativeImplementation = new NativeFunction(
            implementation, 'uint64', ['uint64', 'uint64']);
        const wrapper = new NativeCallback((first, second) => {
          return nativeImplementation(first, second);
        }, 'uint64', ['uint64', 'uint64']);
        const original = Interceptor.replaceFast(replaceTarget, wrapper);
        replacements.set(replaceTarget.toString(), wrapper);
        originalOutput.writePointer(original);
        return 0;
      }, 'int',
      ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
  retainedCallbacks.revert = new NativeCallback(
      (_interceptor, replaceTarget) => {
        Interceptor.revert(replaceTarget);
        const wrapper = replacements.get(replaceTarget.toString());
        if (wrapper !== undefined)
          retiredReplacements.push(wrapper);
        replacements.delete(replaceTarget.toString());
      }, 'void', ['pointer', 'pointer']);
  retainedCallbacks.beginTransaction = new NativeCallback(
      () => { transactionDepth++; }, 'void', ['pointer']);
  retainedCallbacks.endTransaction = new NativeCallback(() => {
    if (transactionDepth > 0)
      transactionDepth--;
    if (transactionDepth === 0)
      Interceptor.flush();
  }, 'void', ['pointer']);
  retainedCallbacks.flush = new NativeCallback(() => {
    Interceptor.flush();
    return 1;
  }, 'int', ['pointer']);

  const size = apiSize();
  const api = Memory.alloc(Number(size));
  api.writeU32(1);
  api.add(4).writeU32(0);
  const functions = [
    NULL,
    NULL,
    retainedCallbacks.obtain,
    retainedCallbacks.objectUnref,
    retainedCallbacks.makeCallListener,
    retainedCallbacks.makeProbeListener,
    retainedCallbacks.attach,
    retainedCallbacks.detach,
    retainedCallbacks.replace,
    retainedCallbacks.revert,
    retainedCallbacks.beginTransaction,
    retainedCallbacks.endTransaction,
    retainedCallbacks.flush,
    contextModule.get_nth_argument,
    contextModule.replace_nth_argument,
    contextModule.get_return_value,
    contextModule.replace_return_value,
    contextModule.get_function,
    contextModule.get_cpu_context,
    contextModule.get_return_address,
    contextModule.get_thread_id,
    contextModule.get_depth,
    contextModule.get_listener_function_data,
    contextModule.get_replacement_data,
    contextModule.get_current_invocation
  ];
  for (let index = 0; index !== functions.length; index++) {
    api.add(8 + index * Process.pointerSize).writePointer(functions[index]);
  }

  const output = Memory.alloc(1024);
  output.writeUtf8String('');
  const result = run(api, size, target, replacement, output, 1024);
  const message = output.readUtf8String() || '';
  if (result !== 0) {
    throw new Error(`native Gum live test failed (${result}): ${message}`);
  }
  console.log(message);
  send({type: 'art-hook-gum-live-result', ok: true, message});
} catch (error) {
  const message = error.stack || error.message || String(error);
  console.log(`GUM_LIVE_TEST_FAIL ${message}`);
  send({type: 'art-hook-gum-live-result', ok: false, message});
}
