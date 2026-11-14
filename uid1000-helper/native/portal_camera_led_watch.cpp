// SPDX-License-Identifier: Apache-2.0
// Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
// See LICENSE and NOTICE.

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

#ifndef PORTAL_UID1000_DATA_DIRECTORY
#define PORTAL_UID1000_DATA_DIRECTORY "/data/portal-uid1000"
#endif

constexpr char kTag[] = "PortalCameraLed";
constexpr char kPresenceTag[] = "PortalPresence";
constexpr char kCameraEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/camera-led-enabled";
constexpr char kPresenceFps[] =
    PORTAL_UID1000_DATA_DIRECTORY "/presence-fps";
constexpr char kWirelessAdbEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/wireless-adb-enabled";
constexpr char kAdbFrameworkEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/adb-framework-enabled";
constexpr char kSystemThemeControlEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/system-theme-control-enabled";
// Android's debug_prop is writable by UID 2000 and non-persistent. The
// root-owned marker above is the durable capability gate.
constexpr char kSystemThemeProperty[] = "debug.portal.system_theme";
constexpr char kSystemThemeTag[] = "PortalSystemTheme";
constexpr char kAdbFrameworkTag[] = "PortalAdbFramework";
constexpr char kClientLibrary[] =
    "/system/lib64/privacystate_client1.0.so";
constexpr char kConstructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientC1EN6vendor8facebook8hardware"
    "12privacystate4V1_09ComponentEjb";
constexpr char kDestructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientD1Ev";
constexpr char kConnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient11connectIntfEv";
constexpr char kDisconnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient14disconnectIntfEv";
constexpr char kClear[] =
    "_ZN8facebook5aloha18PrivacyStateClient8clearLedEv";
constexpr char kGet[] =
    "_ZN8facebook5aloha18PrivacyStateClient6getLedEv";

using Constructor = void (*)(void *, uint8_t, uint32_t, bool);
using Destructor = void (*)(void *);
using ConnectMethod = int (*)(void *);
using BoolMethod = bool (*)(void *);
using VoidMethod = void (*)(void *);

volatile sig_atomic_t running = 1;
volatile sig_atomic_t stop_signal = 0;

using LogVPrint = int (*)(int, const char *, const char *, va_list);
LogVPrint real_log_vprint = nullptr;

int quiet_privacy_log(int priority, const char *tag, const char *format, ...) {
  if (tag != nullptr && strcmp(tag, "PrivacyStateClient") == 0) return 0;
  if (real_log_vprint == nullptr) return 0;
  va_list arguments;
  va_start(arguments, format);
  int result = real_log_vprint(priority, tag, format, arguments);
  va_end(arguments);
  return result;
}

uintptr_t loaded_address(uintptr_t base, uintptr_t value) {
  return value >= base ? value : base + value;
}

int silence_privacy_client_logs(dl_phdr_info *info, size_t, void *) {
  if (info->dlpi_name == nullptr ||
      strstr(info->dlpi_name, "privacystate_client1.0.so") == nullptr) {
    return 0;
  }

  const ElfW(Dyn) *dynamic = nullptr;
  for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
    if (info->dlpi_phdr[index].p_type == PT_DYNAMIC) {
      dynamic = reinterpret_cast<const ElfW(Dyn) *>(
          info->dlpi_addr + info->dlpi_phdr[index].p_vaddr);
      break;
    }
  }
  if (dynamic == nullptr) return 1;

  const ElfW(Rela) *relocations = nullptr;
  size_t relocation_size = 0;
  const ElfW(Sym) *symbols = nullptr;
  const char *strings = nullptr;
  for (const ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; ++entry) {
    switch (entry->d_tag) {
      case DT_JMPREL:
        relocations = reinterpret_cast<const ElfW(Rela) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_PLTRELSZ:
        relocation_size = static_cast<size_t>(entry->d_un.d_val);
        break;
      case DT_SYMTAB:
        symbols = reinterpret_cast<const ElfW(Sym) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_STRTAB:
        strings = reinterpret_cast<const char *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
    }
  }
  if (relocations == nullptr || relocation_size == 0 || symbols == nullptr ||
      strings == nullptr) {
    return 1;
  }

  const long page_size = sysconf(_SC_PAGESIZE);
  const size_t count = relocation_size / sizeof(ElfW(Rela));
  for (size_t index = 0; index < count; ++index) {
    const ElfW(Rela) &relocation = relocations[index];
    size_t symbol_index = ELF64_R_SYM(relocation.r_info);
    const char *name = strings + symbols[symbol_index].st_name;
    if (strcmp(name, "__android_log_print") != 0) continue;
    auto *slot = reinterpret_cast<void **>(
        info->dlpi_addr + relocation.r_offset);
    uintptr_t page = reinterpret_cast<uintptr_t>(slot) &
        ~static_cast<uintptr_t>(page_size - 1);
    if (mprotect(reinterpret_cast<void *>(page), static_cast<size_t>(page_size),
                 PROT_READ | PROT_WRITE) != 0) {
      return 1;
    }
    *slot = reinterpret_cast<void *>(&quiet_privacy_log);
    (void)mprotect(reinterpret_cast<void *>(page),
                   static_cast<size_t>(page_size), PROT_READ);
    return 1;
  }
  return 1;
}

void stop(int signal_number) {
  stop_signal = signal_number;
  running = 0;
}

void *symbol(void *library, const char *name) {
  dlerror();
  void *result = dlsym(library, name);
  const char *error = dlerror();
  if (error != nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag,
                        "missing symbol %s: %s", name, error);
    return nullptr;
  }
  return result;
}

int claim_singleton() {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  constexpr char name[] = "portal.camera.led.watch";
  static_assert(sizeof(name) < sizeof(address.sun_path));
  memcpy(address.sun_path + 1, name, sizeof(name) - 1);
  socklen_t length = static_cast<socklen_t>(
      sizeof(address.sun_family) + 1 + sizeof(name) - 1);
  if (bind(fd, reinterpret_cast<sockaddr *>(&address), length) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int read_presence_fps() {
  int fd = open(kPresenceFps, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return 0;
  char value[16]{};
  ssize_t count = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (count <= 0) return 0;
  char *end = nullptr;
  long fps = strtol(value, &end, 10);
  while (end != nullptr && (*end == '\n' || *end == '\r' || *end == ' ')) {
    ++end;
  }
  return end != nullptr && *end == '\0' && fps >= 1 && fps <= 10
      ? static_cast<int>(fps) : 0;
}

int run_command(const char *const arguments[]) {
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    execv(arguments[0], const_cast<char *const *>(arguments));
    _exit(127);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_command_capture(const char *const arguments[], char *output,
                        size_t output_size) {
  if (output == nullptr || output_size == 0) return -1;
  output[0] = '\0';
  int descriptors[2];
  if (pipe2(descriptors, O_CLOEXEC) != 0) return -1;
  pid_t child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return -1;
  }
  if (child == 0) {
    close(descriptors[0]);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    dup2(descriptors[1], STDOUT_FILENO);
    close(descriptors[1]);
    execv(arguments[0], const_cast<char *const *>(arguments));
    _exit(127);
  }
  close(descriptors[1]);
  size_t used = 0;
  char discard[128];
  for (;;) {
    char *destination = used + 1 < output_size ? output + used : discard;
    size_t available = used + 1 < output_size
        ? output_size - used - 1
        : sizeof(discard);
    ssize_t count = read(descriptors[0], destination, available);
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (destination != discard) used += static_cast<size_t>(count);
  }
  close(descriptors[0]);
  output[used] = '\0';
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

[[noreturn]] void activate_presence(int fps) {
  sleep(15);
  const char *const start[] = {
      "/system/bin/cmd", "activity", "start", "--user", "0", "-n",
      "com.facebook.portal.aiservice/"
      "com.facebook.alohaapp.app.MainActivity", nullptr};
  int activity_status = run_command(start);
  sleep(3);
  const char *const home[] = {
      "/system/bin/cmd", "activity", "start", "--user", "0", "-a",
      "android.intent.action.MAIN", "-c", "android.intent.category.HOME",
      nullptr};
  int home_status = run_command(home);
  if (activity_status == 0 && home_status == 0) {
    __android_log_print(ANDROID_LOG_INFO, kPresenceTag,
                        "presence FPS activation complete fps=%d uid=%d",
                        fps, getuid());
    _exit(0);
  }
  __android_log_print(ANDROID_LOG_ERROR, kPresenceTag,
                      "presence FPS activation failed fps=%d uid=%d "
                      "activity_status=%d home_status=%d",
                      fps, getuid(), activity_status, home_status);
  _exit(1);
}

[[noreturn]] void activate_wireless_adb() {
  // Meta's omni init rules disable adbd late in boot for production builds.
  // Run after that rule, then keep watching because a failed bugreport can
  // also stop adbd later in the same boot. The provisioner separately
  // persists service.adb.tcp.port=5555.
  sleep(20);
  for (;;) {
    char state[PROP_VALUE_MAX]{};
    bool running =
        __system_property_get("init.svc.adbd", state) > 0 &&
        strcmp(state, "running") == 0;
    if (!running) {
      errno = 0;
      int persist_status =
          __system_property_set("persist.sys.usb.config", "adb");
      int persist_errno = errno;
      errno = 0;
      int none_status = __system_property_set("sys.usb.config", "none");
      int none_errno = errno;
      sleep(1);
      errno = 0;
      int adb_status = __system_property_set("sys.usb.config", "adb");
      int adb_errno = errno;
      __android_log_print(
          adb_status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
          kTag,
          "wireless ADB activation uid=%d state=%s persist=%d/%d "
          "none=%d/%d adb=%d/%d",
          getuid(), state[0] ? state : "unset", persist_status,
          persist_errno, none_status, none_errno, adb_status, adb_errno);
    }
    sleep(10);
  }
}

[[noreturn]] void activate_adb_framework() {
  const char *const get_adb_enabled[] = {
      "/system/bin/cmd", "settings", "get", "global", "adb_enabled",
      nullptr};
  const char *const enable_adb_framework[] = {
      "/system/bin/cmd", "settings", "put", "global", "adb_enabled", "1",
      nullptr};
  unsigned int cycles = 0;
  for (;;) {
    // Meta firmware can reset Settings.Global.adb_enabled during boot. Keeping
    // adbd alive is not enough: existing keys still work, but Android cannot
    // show the confirmation dialog for a new host. Check frequently while boot
    // settles, then once per minute, and only write when the value is wrong.
    if (cycles < 12 || cycles % 6 == 0) {
      char adb_enabled[32]{};
      int get_status = run_command_capture(
          get_adb_enabled, adb_enabled, sizeof(adb_enabled));
      char *end = adb_enabled + strlen(adb_enabled);
      while (end > adb_enabled &&
             (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' ||
              end[-1] == '\t')) {
        *--end = '\0';
      }
      if (get_status != 0 || strcmp(adb_enabled, "1") != 0) {
        int put_status = run_command(enable_adb_framework);
        __android_log_print(
            put_status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
            kAdbFrameworkTag,
            "activation uid=%d previous=%s get_status=%d put_status=%d",
            getuid(), adb_enabled[0] ? adb_enabled : "unavailable",
            get_status, put_status);
      }
    }
    ++cycles;
    sleep(10);
  }
}

enum class SystemTheme {
  kNone,
  kLight,
  kDark,
};

SystemTheme requested_system_theme() {
  char value[PROP_VALUE_MAX]{};
  if (__system_property_get(kSystemThemeProperty, value) <= 0) {
    return SystemTheme::kNone;
  }
  if (strcmp(value, "light") == 0) return SystemTheme::kLight;
  if (strcmp(value, "dark") == 0) return SystemTheme::kDark;
  return SystemTheme::kNone;
}

[[noreturn]] void activate_system_theme_control() {
  SystemTheme applied = SystemTheme::kNone;
  for (;;) {
    SystemTheme requested = requested_system_theme();
    if (requested == SystemTheme::kNone) {
      applied = SystemTheme::kNone;
    } else if (requested != applied) {
      const char *const light[] = {
          "/system/bin/cmd", "uimode", "night", "no", nullptr};
      const char *const dark[] = {
          "/system/bin/cmd", "uimode", "night", "yes", nullptr};
      const char *const *arguments =
          requested == SystemTheme::kDark ? dark : light;
      int status = run_command(arguments);
      __android_log_print(
          status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
          kSystemThemeTag,
          "system theme request mode=%s uid=%d status=%d",
          requested == SystemTheme::kDark ? "dark" : "light", getuid(),
          status);
      if (status == 0) applied = requested;
      if (status != 0) sleep(2);
    }
    usleep(250000);
  }
}

bool omni_wireless_adb_requested() {
  char device[PROP_VALUE_MAX]{};
  char port[PROP_VALUE_MAX]{};
  return __system_property_get("ro.product.device", device) > 0 &&
      strcmp(device, "omni") == 0 &&
      __system_property_get("service.adb.tcp.port", port) > 0 &&
      strcmp(port, "5555") == 0;
}

}  // namespace

int portal_watchdog_main(int argc, char **argv) {
  prctl(PR_SET_NAME, "portal-led-watch", 0, 0, 0);
  int singleton = claim_singleton();
  if (singleton < 0) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog already running or socket unavailable: %s",
                        strerror(errno));
    return 0;
  }

  signal(SIGTERM, stop);
  signal(SIGINT, stop);

  bool camera_enabled = access(kCameraEnabled, R_OK) == 0;
  // Omni's production init rules stop adbd after persistent properties load.
  // Treat its persisted TCP port as the durable request too, so a reboot can
  // recover even if the exploit copied this binary but reset before writing
  // the companion marker.
  bool wireless_adb_enabled =
      access(kWirelessAdbEnabled, R_OK) == 0 ||
      omni_wireless_adb_requested();
  bool system_theme_control_enabled =
      access(kSystemThemeControlEnabled, R_OK) == 0;
  bool adb_framework_enabled =
      access(kAdbFrameworkEnabled, R_OK) == 0;
  int presence_fps = read_presence_fps();
  for (int index = 1; index < argc; ++index) {
    if (strcmp(argv[index], "--camera") == 0) {
      camera_enabled = true;
    } else if (strcmp(argv[index], "--fps") == 0 && index + 1 < argc) {
      char *end = nullptr;
      long value = strtol(argv[++index], &end, 10);
      if (end != nullptr && *end == '\0' && value >= 1 && value <= 10) {
        presence_fps = static_cast<int>(value);
      }
    } else if (strcmp(argv[index], "--adb-framework") == 0) {
      adb_framework_enabled = true;
    }
  }
  pid_t presence_worker = -1;
  if (presence_fps != 0) {
    presence_worker = fork();
    if (presence_worker == 0) {
      close(singleton);
      activate_presence(presence_fps);
    }
    if (presence_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kPresenceTag,
                          "could not start presence worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t wireless_adb_worker = -1;
  if (wireless_adb_enabled) {
    wireless_adb_worker = fork();
    if (wireless_adb_worker == 0) {
      close(singleton);
      activate_wireless_adb();
    }
    if (wireless_adb_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kTag,
                          "could not start wireless ADB worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t adb_framework_worker = -1;
  if (adb_framework_enabled) {
    adb_framework_worker = fork();
    if (adb_framework_worker == 0) {
      close(singleton);
      activate_adb_framework();
    }
    if (adb_framework_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kAdbFrameworkTag,
                          "could not start worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t system_theme_worker = -1;
  if (system_theme_control_enabled) {
    system_theme_worker = fork();
    if (system_theme_worker == 0) {
      close(singleton);
      activate_system_theme_control();
    }
    if (system_theme_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kSystemThemeTag,
                          "could not start system theme worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }

  if (!camera_enabled) {
    if (presence_worker > 0) {
      int status = 0;
      while (waitpid(presence_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    if (wireless_adb_worker > 0) {
      int status = 0;
      while (waitpid(wireless_adb_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    if (adb_framework_worker > 0) {
      int status = 0;
      while (waitpid(adb_framework_worker, &status, 0) < 0 &&
             errno == EINTR) {}
    }
    if (system_theme_worker > 0) {
      int status = 0;
      while (waitpid(system_theme_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    close(singleton);
    return presence_fps != 0 || wireless_adb_enabled ||
        adb_framework_enabled || system_theme_control_enabled ? 0 : 1;
  }

  void *library = dlopen(kClientLibrary, RTLD_NOW | RTLD_LOCAL);
  if (library == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "dlopen failed: %s",
                        dlerror());
    return 1;
  }
  real_log_vprint = reinterpret_cast<LogVPrint>(
      dlsym(RTLD_DEFAULT, "__android_log_vprint"));
  dl_iterate_phdr(silence_privacy_client_logs, nullptr);
  auto constructor = reinterpret_cast<Constructor>(symbol(library, kConstructor));
  auto destructor = reinterpret_cast<Destructor>(symbol(library, kDestructor));
  auto connect = reinterpret_cast<ConnectMethod>(symbol(library, kConnect));
  auto disconnect = reinterpret_cast<VoidMethod>(symbol(library, kDisconnect));
  auto clear = reinterpret_cast<BoolMethod>(symbol(library, kClear));
  auto get = reinterpret_cast<BoolMethod>(symbol(library, kGet));
  if (constructor == nullptr || destructor == nullptr || connect == nullptr ||
      disconnect == nullptr || clear == nullptr || get == nullptr) {
    dlclose(library);
    return 1;
  }

  alignas(16) unsigned char client[0x100]{};
  constructor(client, 0, 0, true);
  bool connected = connect(client) == 0;
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog started uid=%d", getuid());
  if (connected) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog connected uid=%d", getuid());
  }

  unsigned failures = 0;
  unsigned reconnect_ticks = 0;
  unsigned heartbeat_ticks = 0;
  while (running) {
    if (!connected) {
      if (++reconnect_ticks >= 20) {
        reconnect_ticks = 0;
        connected = connect(client) == 0;
        if (connected) {
          failures = 0;
          __android_log_print(ANDROID_LOG_INFO, kTag,
                              "watchdog connected uid=%d", getuid());
        }
      }
    } else {
      bool should_clear = get(client) || ++heartbeat_ticks >= 240;
      if (should_clear) {
        heartbeat_ticks = 0;
        if (clear(client)) {
          failures = 0;
        } else if (++failures >= 20) {
          __android_log_print(ANDROID_LOG_WARN, kTag,
                              "clearLed failed; reconnecting");
          disconnect(client);
          connected = false;
          failures = 0;
          reconnect_ticks = 0;
        }
      }
    }
    usleep(250000);
  }

  if (connected) disconnect(client);
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog exiting signal=%d", stop_signal);
  destructor(client);
  dlclose(library);
  close(singleton);
  return 0;
}

#ifndef PORTAL_WATCHDOG_LIBRARY
int main(int argc, char **argv) {
  return portal_watchdog_main(argc, argv);
}
#endif
