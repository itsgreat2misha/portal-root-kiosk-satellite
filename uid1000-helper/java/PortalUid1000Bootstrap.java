// SPDX-License-Identifier: Apache-2.0
// Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
// See LICENSE and NOTICE.

public final class PortalUid1000Bootstrap {
  private static native void run(int configuration);

  public static void main(String[] arguments) {
    if (arguments.length == 0) {
      throw new IllegalArgumentException("watchdog library path is required");
    }
    int configuration = 0;
    for (int index = 1; index < arguments.length; ++index) {
      if ("--camera".equals(arguments[index])) {
        configuration |= 0x100;
      } else if ("--adb-framework".equals(arguments[index])) {
        configuration |= 0x200;
      } else if ("--fps".equals(arguments[index]) && index + 1 < arguments.length) {
        int fps = Integer.parseInt(arguments[++index]);
        if (fps < 1 || fps > 10) {
          throw new IllegalArgumentException("FPS must be between 1 and 10");
        }
        configuration |= fps;
      }
    }
    System.load(arguments[0]);
    run(configuration);
  }

  private PortalUid1000Bootstrap() {}
}
