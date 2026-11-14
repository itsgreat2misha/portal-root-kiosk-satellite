// SPDX-License-Identifier: Apache-2.0
// Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
// See LICENSE and NOTICE.

#define _GNU_SOURCE

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <unistd.h>

#define TAG "PortalAudioPersist"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define AUDIO_CTL_JAR \
  "/data/user/0/com.facebook.portal.aiservice/lib-compressed/" \
  "portal-audio-ctl.jar"

static int uses_mha_backend(void) {
  char device[PROP_VALUE_MAX] = {0};
  return __system_property_get("ro.product.device", device) > 0 &&
      strcmp(device, "omni") == 0;
}

static int run_audio_ctl(void) {
  pid_t pid = fork();
  if (pid < 0) return 0;
  if (pid == 0) {
    unsetenv("LD_PRELOAD");
    setenv("CLASSPATH", AUDIO_CTL_JAR, 1);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      (void)dup2(null_fd, STDIN_FILENO);
      (void)dup2(null_fd, STDOUT_FILENO);
      (void)dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    execl("/system/bin/app_process32", "app_process", "/system/bin",
          "PortalAudioCtl", "3001", "0", "4001", "0", (char *)NULL);
    execl("/system/bin/app_process", "app_process", "/system/bin",
          "PortalAudioCtl", "3001", "0", "4001", "0", (char *)NULL);
    _exit(127);
  }

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void *watchdog_main(void *unused) {
  (void)unused;
  static const unsigned int healthy_delays[] = {2, 3, 5, 10, 15, 30, 60};
  unsigned int healthy_checks = 0;
  unsigned int failures = 0;
  int mha = uses_mha_backend();
  sleep(2);
  for (;;) {
    int ok = run_audio_ctl();
    if (ok) {
      if (failures)
        LOGI("audio processing restored after %u failures backend=java", failures);
      if (healthy_checks == 0) {
        if (mha)
          LOGI("mha audio processing verified aec=0 ns=0 backend=java");
        else
          LOGI("audio processing verified aec=0 ns=0 backend=java");
      }
      failures = 0;
      unsigned int index = healthy_checks;
      if (index >= sizeof(healthy_delays) / sizeof(healthy_delays[0]))
        index = sizeof(healthy_delays) / sizeof(healthy_delays[0]) - 1;
      healthy_checks++;
      sleep(healthy_delays[index]);
    } else {
      failures++;
      if (failures == 1 || failures % 30 == 0)
        LOGE("audio processing apply failed count=%u backend=java", failures);
      healthy_checks = 0;
      sleep(2);
    }
  }
  return NULL;
}

__attribute__((constructor)) static void portal_audio_start(void) {
  pthread_t thread;
  int error = pthread_create(&thread, NULL, watchdog_main, NULL);
  if (error == 0) {
    pthread_detach(thread);
    LOGI("persistent audio watchdog started backend=java dsp=%s",
         uses_mha_backend() ? "mha" : "voice-param");
  } else {
    LOGE("watchdog pthread_create failed error=%d backend=java", error);
  }
}
