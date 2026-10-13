#include <jni.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <rtgum/kpm_supercall.h>

namespace {

constexpr const char *kEnrollmentKey = "rtgum-manager";
constexpr const char *kModuleName = "rtgum-stage1";
constexpr std::size_t kResponseSize = 1024U;

jstring Result(JNIEnv *env, long status, const char *response) {
  char text[kResponseSize + 64U];
  if (status == 0 && response != nullptr && response[0] != '\0') {
    std::snprintf(text, sizeof(text), "%s", response);
  } else {
    std::snprintf(text, sizeof(text), "error=supercall-failed code=%ld errno=%d",
                  status, errno);
  }
  return env->NewStringUTF(text);
}

bool ValidSession(const char *session) {
  if (session == nullptr || std::strlen(session) != 64U) return false;
  for (const char *cursor = session; *cursor != '\0'; ++cursor) {
    if (!((*cursor >= '0' && *cursor <= '9') ||
          (*cursor >= 'a' && *cursor <= 'f') ||
          (*cursor >= 'A' && *cursor <= 'F')))
      return false;
  }
  return true;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_dev_rtgum_manager_MainActivity_nativeEnroll(JNIEnv *env, jclass) {
  char response[kResponseSize]{};
  const long status = rtgum_sc_kpm_control(
      kEnrollmentKey, kModuleName, "session-manager", response,
      static_cast<long>(sizeof(response)));
  return Result(env, status, response);
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_rtgum_manager_MainActivity_nativeControl(JNIEnv *env, jclass,
                                                   jstring session_value,
                                                   jstring command_value) {
  if (session_value == nullptr || command_value == nullptr)
    return env->NewStringUTF("error=invalid-arguments");
  const char *session = env->GetStringUTFChars(session_value, nullptr);
  const char *command = env->GetStringUTFChars(command_value, nullptr);
  if (session == nullptr || command == nullptr) {
    if (session != nullptr) env->ReleaseStringUTFChars(session_value, session);
    if (command != nullptr) env->ReleaseStringUTFChars(command_value, command);
    env->ExceptionClear();
    return env->NewStringUTF("error=utf-conversion-failed");
  }

  char authenticated[1024];
  const int length = ValidSession(session)
                         ? std::snprintf(authenticated, sizeof(authenticated),
                                         "auth %s %s", session, command)
                         : -1;
  env->ReleaseStringUTFChars(session_value, session);
  env->ReleaseStringUTFChars(command_value, command);
  if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(authenticated))
    return env->NewStringUTF("error=invalid-command");

  char response[kResponseSize]{};
  const long status = rtgum_sc_kpm_control(
      kEnrollmentKey, kModuleName, authenticated, response,
      static_cast<long>(sizeof(response)));
  return Result(env, status, response);
}
