// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/class_factory.h"

#include <algorithm>
#include <utility>

#include "art_hook/jni_result.h"
#include "art_hook/jni_types.h"

namespace art_hook {

Result<LocalRef<jclass>> ClassFactory::Use(std::string class_name) const {
  if (!class_name.empty() && class_name.front() == 'L' &&
      class_name.back() == ';') {
    class_name = class_name.substr(1, class_name.size() - 2);
  }
  std::replace(class_name.begin(), class_name.end(), '.', '/');
  return env_.FindClass(class_name.c_str());
}

Status ClassFactory::RegisterNatives(
    jclass klass, const std::vector<NativeMethod>& methods) const {
  if (klass == nullptr) {
    return Status(StatusCode::kInvalidArgument, "class is null");
  }
  std::vector<JNINativeMethod> native_methods;
  native_methods.reserve(methods.size());
  for (const auto& method : methods) {
    if (method.name.empty() || method.function == nullptr) {
      return Status(StatusCode::kInvalidArgument,
                    "native method requires a name and function");
    }
    auto descriptor = ParseMethodDescriptor(method.signature);
    if (!descriptor.ok()) {
      return descriptor.status();
    }
    native_methods.push_back(
        {const_cast<char*>(method.name.c_str()),
         const_cast<char*>(method.signature.c_str()), method.function});
  }
  const jint result = env_.get()->RegisterNatives(
      klass, native_methods.data(), static_cast<jint>(native_methods.size()));
  Status status = CheckJniResult("JNIEnv::RegisterNatives", result);
  if (!status.ok()) {
    const Status exception =
        env_.ExceptionStatus("JNIEnv::RegisterNatives");
    if (!exception.ok()) {
      return exception;
    }
  }
  return status;
}

Result<LocalRef<jobject>> ClassFactory::LoadDex(
    const std::vector<std::uint8_t>& dex, jobject parent_loader) const {
  if (dex.empty()) {
    return Status(StatusCode::kInvalidArgument, "DEX buffer is empty");
  }
  JNIEnv* jni = env_.get();
  LocalRef<jbyteArray> bytes(
      jni, jni->NewByteArray(static_cast<jsize>(dex.size())));
  Status status = env_.ExceptionStatus("NewByteArray(DEX)");
  if (!status.ok() || !bytes) {
    return status.ok()
               ? Status(StatusCode::kResourceExhausted,
                        "unable to allocate DEX byte array")
               : status;
  }
  jni->SetByteArrayRegion(bytes.get(), 0, static_cast<jsize>(dex.size()),
                          reinterpret_cast<const jbyte*>(dex.data()));
  status = env_.ExceptionStatus("SetByteArrayRegion(DEX)");
  if (!status.ok()) {
    return status;
  }

  auto byte_buffer_class = env_.FindClass("java/nio/ByteBuffer");
  if (!byte_buffer_class.ok()) {
    return byte_buffer_class.status();
  }
  jmethodID wrap = jni->GetStaticMethodID(
      byte_buffer_class.value().get(), "wrap", "([B)Ljava/nio/ByteBuffer;");
  status = env_.ExceptionStatus("ByteBuffer.wrap lookup");
  if (!status.ok() || wrap == nullptr) {
    return status.ok()
               ? Status(StatusCode::kNotFound, "ByteBuffer.wrap unavailable")
               : status;
  }
  LocalRef<jobject> buffer(
      jni, jni->CallStaticObjectMethod(byte_buffer_class.value().get(), wrap,
                                       bytes.get()));
  status = env_.ExceptionStatus("ByteBuffer.wrap");
  if (!status.ok()) {
    return status;
  }

  if (parent_loader == nullptr) {
    auto loader_class = env_.FindClass("java/lang/ClassLoader");
    if (!loader_class.ok()) {
      return loader_class.status();
    }
    jmethodID get_system = jni->GetStaticMethodID(
        loader_class.value().get(), "getSystemClassLoader",
        "()Ljava/lang/ClassLoader;");
    status = env_.ExceptionStatus("ClassLoader.getSystemClassLoader lookup");
    if (!status.ok() || get_system == nullptr) {
      return status.ok()
                 ? Status(StatusCode::kNotFound,
                          "system class loader is unavailable")
                 : status;
    }
    parent_loader = jni->CallStaticObjectMethod(loader_class.value().get(),
                                                 get_system);
    status = env_.ExceptionStatus("ClassLoader.getSystemClassLoader");
    if (!status.ok()) {
      return status;
    }
  }

  auto in_memory_loader = env_.FindClass("dalvik/system/InMemoryDexClassLoader");
  if (!in_memory_loader.ok()) {
    return Status(StatusCode::kUnsupported,
                  "InMemoryDexClassLoader requires Android 8.0 or newer");
  }
  jmethodID constructor = jni->GetMethodID(
      in_memory_loader.value().get(), "<init>",
      "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
  status = env_.ExceptionStatus("InMemoryDexClassLoader constructor lookup");
  if (!status.ok() || constructor == nullptr) {
    return status.ok()
               ? Status(StatusCode::kNotFound,
                        "InMemoryDexClassLoader constructor unavailable")
               : status;
  }
  jobject loader = jni->NewObject(in_memory_loader.value().get(), constructor,
                                  buffer.get(), parent_loader);
  status = env_.ExceptionStatus("InMemoryDexClassLoader construction");
  if (!status.ok()) {
    return status;
  }
  return LocalRef<jobject>(jni, loader);
}

Result<LocalRef<jclass>> ClassFactory::LoadClass(
    jobject loader, std::string class_name) const {
  if (loader == nullptr || class_name.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "LoadClass requires a loader and class name");
  }
  if (class_name.front() == 'L' && class_name.back() == ';') {
    class_name = class_name.substr(1, class_name.size() - 2);
  }
  std::replace(class_name.begin(), class_name.end(), '/', '.');
  JNIEnv* jni = env_.get();
  LocalRef<jclass> loader_class(jni, jni->GetObjectClass(loader));
  jmethodID load_class = jni->GetMethodID(
      loader_class.get(), "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  Status status = env_.ExceptionStatus("ClassLoader.loadClass lookup");
  if (!status.ok() || load_class == nullptr) {
    return status.ok()
               ? Status(StatusCode::kNotFound, "ClassLoader.loadClass unavailable")
               : status;
  }
  auto name = env_.NewStringUtf(class_name);
  if (!name.ok()) {
    return name.status();
  }
  jclass klass = static_cast<jclass>(
      jni->CallObjectMethod(loader, load_class, name.value().get()));
  status = env_.ExceptionStatus("ClassLoader.loadClass");
  if (!status.ok()) {
    return status;
  }
  return LocalRef<jclass>(jni, klass);
}

}  // namespace art_hook
