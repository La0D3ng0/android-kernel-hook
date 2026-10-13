// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/runtime_api.h"

#include <array>
#include <utility>

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <dlfcn.h>
#endif

namespace art_hook {
namespace {

std::string Architecture() {
#if defined(__aarch64__)
  return "arm64";
#elif defined(__arm__)
  return "arm";
#elif defined(__x86_64__)
  return "x86_64";
#elif defined(__i386__)
  return "x86";
#else
  return "unknown";
#endif
}

std::string AndroidProperty(const char* name) {
#if defined(__ANDROID__)
  std::array<char, PROP_VALUE_MAX> value{};
  const int length = __system_property_get(name, value.data());
  return length > 0 ? std::string(value.data(), static_cast<std::size_t>(length))
                    : std::string();
#else
  (void)name;
  return {};
#endif
}

void* LookupDefault(const char* name) {
#if defined(__ANDROID__) || defined(__unix__) || defined(__APPLE__)
  return dlsym(RTLD_DEFAULT, name);
#else
  (void)name;
  return nullptr;
#endif
}

}  // namespace

RuntimeApi::~RuntimeApi() {
#if defined(__ANDROID__) || defined(__unix__) || defined(__APPLE__)
  if (libart_ != nullptr) {
    dlclose(libart_);
  }
#endif
}

RuntimeApi::RuntimeApi(RuntimeApi&& other) noexcept
    : info_(std::move(other.info_)),
      vm_(other.vm_),
      jvmti_(other.jvmti_),
      libart_(other.libart_) {
  other.vm_ = nullptr;
  other.jvmti_ = nullptr;
  other.libart_ = nullptr;
}

RuntimeApi& RuntimeApi::operator=(RuntimeApi&& other) noexcept {
  if (this != &other) {
#if defined(__ANDROID__) || defined(__unix__) || defined(__APPLE__)
    if (libart_ != nullptr) {
      dlclose(libart_);
    }
#endif
    info_ = std::move(other.info_);
    vm_ = other.vm_;
    jvmti_ = other.jvmti_;
    libart_ = other.libart_;
    other.vm_ = nullptr;
    other.jvmti_ = nullptr;
    other.libart_ = nullptr;
  }
  return *this;
}

Result<RuntimeApi> RuntimeApi::Discover(JavaVM* known_vm) {
  RuntimeApi api;
  api.info_.architecture = Architecture();

#if defined(__ANDROID__)
  api.info_.flavor = RuntimeFlavor::kArt;
  api.info_.android_api_level = android_get_device_api_level();
  api.info_.android_release = AndroidProperty("ro.build.version.release");
  api.libart_ = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
  api.info_.has_libart = api.libart_ != nullptr;
#else
  api.info_.flavor = RuntimeFlavor::kHotSpot;
#endif

  api.vm_ = known_vm;
  // Android's libnativehelper may export an invocation stub that aborts when
  // called outside a managed process. Only query it if ART is already loaded.
  const bool can_query_created_vms =
#if defined(__ANDROID__)
      api.info_.has_libart;
#else
      true;
#endif
  if (api.vm_ == nullptr && can_query_created_vms) {
    using GetCreatedVms = jint (*)(JavaVM**, jsize, jsize*);
    auto get_created = reinterpret_cast<GetCreatedVms>(
        LookupDefault("JNI_GetCreatedJavaVMs"));
    if (get_created != nullptr) {
      JavaVM* vm = nullptr;
      jsize count = 0;
      if (get_created(&vm, 1, &count) == JNI_OK && count > 0) {
        api.vm_ = vm;
      }
    }
  }
  api.info_.has_java_vm = api.vm_ != nullptr;

  if (api.vm_ != nullptr) {
    void* jvmti = nullptr;
    if (api.vm_->GetEnv(&jvmti, kJvmtiVersion1_2) == JNI_OK) {
      api.jvmti_ = jvmti;
      api.info_.has_jvmti = true;
    }
  }

  return api;
}

void* RuntimeApi::FindArtSymbol(const char* name) const noexcept {
  if (name == nullptr) {
    return nullptr;
  }
#if defined(__ANDROID__) || defined(__unix__) || defined(__APPLE__)
  return libart_ != nullptr ? dlsym(libart_, name) : nullptr;
#else
  return nullptr;
#endif
}

Status RuntimeApi::RequireArtMutationBackend() const {
  if (info_.flavor != RuntimeFlavor::kArt || !info_.has_libart) {
    return Status(StatusCode::kUnavailable, "ART runtime is not loaded");
  }
  return Status(
      StatusCode::kUnsupported,
      "no versioned ART mutation backend passed structural and ABI probes");
}

const char* RuntimeFlavorName(RuntimeFlavor flavor) noexcept {
  switch (flavor) {
    case RuntimeFlavor::kArt:
      return "art";
    case RuntimeFlavor::kDalvik:
      return "dalvik";
    case RuntimeFlavor::kHotSpot:
      return "hotspot";
    case RuntimeFlavor::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace art_hook
