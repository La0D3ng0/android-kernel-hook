// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/gum_interceptor_devkit.h"

#include <gum/gum.h>
#include <gum/guminterceptor.h>
#include <gum/guminvocationcontext.h>
#include <gum/guminvocationlistener.h>

#include <glib-object.h>

namespace art_hook {
namespace {

void InitEmbedded() { gum_init_embedded(); }
void DeinitEmbedded() { gum_deinit_embedded(); }
void *Obtain() { return gum_interceptor_obtain(); }
void ObjectUnref(void *object) { g_object_unref(object); }

void *MakeCallListener(GumInterceptorApi::RawInvocationCallback on_enter,
                       GumInterceptorApi::RawInvocationCallback on_leave,
                       void *data,
                       GumInterceptorApi::DestroyNotify data_destroy) {
  return gum_make_call_listener(
      reinterpret_cast<::GumInvocationCallback>(on_enter),
      reinterpret_cast<::GumInvocationCallback>(on_leave), data,
      data_destroy);
}

void *MakeProbeListener(GumInterceptorApi::RawInvocationCallback on_hit,
                        void *data,
                        GumInterceptorApi::DestroyNotify data_destroy) {
  return gum_make_probe_listener(
      reinterpret_cast<::GumInvocationCallback>(on_hit), data, data_destroy);
}

int Attach(void *interceptor, void *target, void *listener,
           void *listener_function_data) {
#if defined(ART_HOOK_FRIDA_GUM_OPTIONS_API)
  ::GumAttachOptions options{};
  options.listener_function_data = listener_function_data;
  return gum_interceptor_attach(static_cast<::GumInterceptor *>(interceptor),
                                target,
                                static_cast<::GumInvocationListener *>(listener),
                                &options);
#else
  return gum_interceptor_attach(static_cast<::GumInterceptor *>(interceptor),
                                target,
                                static_cast<::GumInvocationListener *>(listener),
                                listener_function_data);
#endif
}

void Detach(void *interceptor, void *listener) {
  gum_interceptor_detach(static_cast<::GumInterceptor *>(interceptor),
                         static_cast<::GumInvocationListener *>(listener));
}

int Replace(void *interceptor, void *target, void *replacement,
            void *replacement_data, void **original_function) {
#if defined(ART_HOOK_FRIDA_GUM_OPTIONS_API)
  ::GumReplaceOptions options{};
  options.replacement_data = replacement_data;
  return gum_interceptor_replace(static_cast<::GumInterceptor *>(interceptor),
                                 target, replacement, original_function,
                                 &options);
#else
  return gum_interceptor_replace(static_cast<::GumInterceptor *>(interceptor),
                                 target, replacement, replacement_data,
                                 original_function);
#endif
}

void Revert(void *interceptor, void *target) {
  gum_interceptor_revert(static_cast<::GumInterceptor *>(interceptor), target);
}

void BeginTransaction(void *interceptor) {
  gum_interceptor_begin_transaction(
      static_cast<::GumInterceptor *>(interceptor));
}

void EndTransaction(void *interceptor) {
  gum_interceptor_end_transaction(static_cast<::GumInterceptor *>(interceptor));
}

int Flush(void *interceptor) {
  return gum_interceptor_flush(static_cast<::GumInterceptor *>(interceptor));
}

void *GetNthArgument(void *context, std::uint32_t index) {
  return gum_invocation_context_get_nth_argument(
      static_cast<::GumInvocationContext *>(context), index);
}

void ReplaceNthArgument(void *context, std::uint32_t index, void *value) {
  gum_invocation_context_replace_nth_argument(
      static_cast<::GumInvocationContext *>(context), index, value);
}

void *GetReturnValue(void *context) {
  return gum_invocation_context_get_return_value(
      static_cast<::GumInvocationContext *>(context));
}

void ReplaceReturnValue(void *context, void *value) {
  gum_invocation_context_replace_return_value(
      static_cast<::GumInvocationContext *>(context), value);
}

void *GetFunction(void *context) {
  return static_cast<::GumInvocationContext *>(context)->function;
}

void *GetCpuContext(void *context) {
  return static_cast<::GumInvocationContext *>(context)->cpu_context;
}

void *GetReturnAddress(void *context) {
  return gum_invocation_context_get_return_address(
      static_cast<::GumInvocationContext *>(context));
}

std::uint64_t GetThreadId(void *context) {
  return gum_invocation_context_get_thread_id(
      static_cast<::GumInvocationContext *>(context));
}

std::uint32_t GetDepth(void *context) {
  return gum_invocation_context_get_depth(
      static_cast<::GumInvocationContext *>(context));
}

void *GetListenerFunctionData(void *context) {
  return gum_invocation_context_get_listener_function_data(
      static_cast<::GumInvocationContext *>(context));
}

void *GetReplacementData(void *context) {
  return gum_invocation_context_get_replacement_data(
      static_cast<::GumInvocationContext *>(context));
}

void *GetCurrentInvocation() { return gum_interceptor_get_current_invocation(); }

} // namespace

GumInterceptorApi MakeFridaGumInterceptorApi() noexcept {
  GumInterceptorApi api;
  api.init_embedded = InitEmbedded;
  api.deinit_embedded = DeinitEmbedded;
  api.obtain = Obtain;
  api.object_unref = ObjectUnref;
  api.make_call_listener = MakeCallListener;
  api.make_probe_listener = MakeProbeListener;
  api.attach = Attach;
  api.detach = Detach;
  api.replace = Replace;
  api.revert = Revert;
  api.begin_transaction = BeginTransaction;
  api.end_transaction = EndTransaction;
  api.flush = Flush;
  api.get_nth_argument = GetNthArgument;
  api.replace_nth_argument = ReplaceNthArgument;
  api.get_return_value = GetReturnValue;
  api.replace_return_value = ReplaceReturnValue;
  api.get_function = GetFunction;
  api.get_cpu_context = GetCpuContext;
  api.get_return_address = GetReturnAddress;
  api.get_thread_id = GetThreadId;
  api.get_depth = GetDepth;
  api.get_listener_function_data = GetListenerFunctionData;
  api.get_replacement_data = GetReplacementData;
  api.get_current_invocation = GetCurrentInvocation;
  return api;
}

} // namespace art_hook
