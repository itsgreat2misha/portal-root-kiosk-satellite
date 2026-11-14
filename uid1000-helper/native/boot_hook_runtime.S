/* SPDX-License-Identifier: Apache-2.0
 * Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
 * See LICENSE and NOTICE. */

    .section .text
    .balign 4
    .global portal_uid1000_boot_hook
    .type portal_uid1000_boot_hook, %function
portal_uid1000_boot_hook:
    // Preserve the managed quick ABI state before making raw syscalls.
    sub     sp, sp, #112
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    str     x30, [sp, #96]
    mrs     x30, nzcv
    str     x30, [sp, #104]

    // clone(SIGCHLD, NULL, NULL, NULL, NULL)
    mov     x0, #17
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #220
    svc     #0
    cbz     x0, child

    ldr     x30, [sp, #104]
    msr     nzcv, x30
    ldr     x30, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #112

    // Re-run the displaced locked-boot receiver instruction.
    sub     x16, sp, #0x2000
    // The installer replaces this with a branch to the receiver + 4.
    .word   0x14000000

    // The installer replaces this word with bit 9=ADB framework,
    // bit 8=camera, and bits 0-7=FPS.
config_word:
    .word   0x50434647

child:
    // Run the stock ART command runner with the minimum Android environment
    // required for ICU and the runtime to initialize. The installer replaces
    // the two padded path placeholders with files from the small runtime APK;
    // apk_data_file is executable by the stock system_app policy.
    sub     sp, sp, #128
    adr     x5, app_process_name
    str     x5, [sp, #0]
    adr     x5, app_process_root
    str     x5, [sp, #8]
    adr     x5, bootstrap_class
    str     x5, [sp, #16]
    adr     x5, watchdog_library
    str     x5, [sp, #24]
    add     x6, sp, #32
    adr     x7, config_word
    ldr     w22, [x7]
    tbz     w22, #8, no_camera
    adr     x5, camera_option
    str     x5, [x6], #8
no_camera:
    and     w23, w22, #0xff
    cbz     w23, no_fps
    adr     x5, fps_option
    str     x5, [x6], #8
    sub     w23, w23, #1
    mov     w24, #3
    mul     w23, w23, w24
    adr     x5, fps_values
    add     x5, x5, x23
    str     x5, [x6], #8
no_fps:
    tbz     w22, #9, no_adb_framework
    adr     x5, adb_framework_option
    str     x5, [x6], #8
no_adb_framework:
    str     xzr, [x6]

    adr     x5, classpath_environment
    str     x5, [sp, #80]
    adr     x5, android_root_environment
    str     x5, [sp, #88]
    adr     x5, android_data_environment
    str     x5, [sp, #96]
    adr     x5, android_storage_environment
    str     x5, [sp, #104]
    str     xzr, [sp, #112]

    // execve("/system/bin/app_process64", argv, envp)
    adr     x0, app_process_path
    mov     x1, sp
    add     x2, sp, #80
    mov     x8, #221
    svc     #0

child_exit:
    mov     x0, #127
    mov     x8, #93
    svc     #0
    brk     #0

app_process_path:
    .asciz  "/system/bin/app_process64"
app_process_name:
    .asciz  "portal-camera-led-watch"
app_process_root:
    .asciz  "/system/bin"
bootstrap_class:
    .asciz  "PortalUid1000Bootstrap"
watchdog_library:
    .asciz  "PORTAL_UID1000_LIBRARY_PATH"
    .space  192 - (. - watchdog_library)
classpath_environment:
    .asciz  "CLASSPATH=PORTAL_UID1000_APK_PATH"
    .space  256 - (. - classpath_environment)
android_root_environment:
    .asciz  "ANDROID_ROOT=/system"
android_data_environment:
    .asciz  "ANDROID_DATA=/data"
android_storage_environment:
    .asciz  "ANDROID_STORAGE=/storage"
camera_option:
    .asciz  "--camera"
fps_option:
    .asciz  "--fps"
adb_framework_option:
    .asciz  "--adb-framework"
fps_values:
    .ascii  "1\0\0" "2\0\0" "3\0\0" "4\0\0" "5\0\0"
    .ascii  "6\0\0" "7\0\0" "8\0\0" "9\0\0" "10\0"
    .balign 4
    .size portal_uid1000_boot_hook, .-portal_uid1000_boot_hook
