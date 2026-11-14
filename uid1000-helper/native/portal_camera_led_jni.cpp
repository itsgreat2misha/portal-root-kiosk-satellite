// SPDX-License-Identifier: Apache-2.0
// Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
// See LICENSE and NOTICE.

#include <jni.h>
#include <stdio.h>

int portal_watchdog_main(int argc, char **argv);

extern "C" JNIEXPORT void JNICALL
Java_PortalUid1000Bootstrap_run(JNIEnv *, jclass, jint configuration) {
  char fps[4]{};
  char program[] = "portal-camera-led-watch";
  char camera[] = "--camera";
  char adb_framework[] = "--adb-framework";
  char fps_option[] = "--fps";
  char *arguments[7] = {
      program, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  int count = 1;
  if ((configuration & 0x100) != 0) {
    arguments[count++] = camera;
  }
  if ((configuration & 0x200) != 0) {
    arguments[count++] = adb_framework;
  }
  int requested_fps = configuration & 0xff;
  if (requested_fps >= 1 && requested_fps <= 10) {
    snprintf(fps, sizeof(fps), "%d", requested_fps);
    arguments[count++] = fps_option;
    arguments[count++] = fps;
  }
  arguments[count] = nullptr;
  (void)portal_watchdog_main(count, arguments);
}
