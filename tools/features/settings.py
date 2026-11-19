#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

"""Settings feature cluster for the host provisioner.

Owns the settings-and-PackageManager features extracted in Phase
M3.2 of the monolith split: debloat (package + component backups,
apply/restore/verify), Meta account removal preflight/verify,
remote-wipe component block/restore, and Private DNS
backup/apply/restore/verify. The provisioner holds a SettingsFeature
and delegates through thin wrappers so existing call sites are
unchanged. Device-operation order, console markers, backup file
formats, and log strings are frozen.

The three device-state readers (package_sets,
current_component_states, current_named_component_states) are
implemented here, but internal callers reach them through the
late-bound callables supplied at construction (which route via the
provisioner's own wrappers), preserving the test suite's ability to
patch those readers on the provisioner. push_text_atomic and
settle_package_state remain provisioner spine utilities and are
likewise supplied late-bound.
"""

from __future__ import annotations

import collections
import dataclasses
import json
import pathlib
import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Callable

from device_session import ProvisionError
from meta_debloat_components import (
    DEBLOAT_COMPONENT_PROFILES,
    DEBLOAT_COMPONENTS,
    DEBLOAT_COMPONENT_NAMES,
)
from portal_targets import PortalTarget

PRIVACY_BACKUP_REMOTE = "/data/local/tmp/portal-private-dns-before-v1.json"
DEBLOAT_BACKUP_REMOTE = "/data/local/tmp/portal-debloat-backup-v1.tsv"
DEBLOAT_COMPONENT_BACKUP_REMOTE = (
    "/data/local/tmp/portal-debloat-components-backup-v1.tsv"
)
DEBLOAT_COMPONENT_ACTIONS_REMOTE = (
    "/data/local/tmp/portal-debloat-components-actions-v1.tsv"
)
REMOTE_WIPE_BACKUP_REMOTE = (
    "/data/local/tmp/portal-remote-wipe-components-backup-v1.tsv"
)
REMOTE_WIPE_COMPONENTS = (
    "com.facebook.alohaservices.deviceadmin/"
    "com.facebook.aloha.system.deviceadmin.remotewipe.FactoryResetReceiver",
    "com.facebook.alohaservices.deviceadmin/"
    "com.facebook.aloha.system.deviceadmin.remotewipe.RemoteWipeReceiver",
)
DEBLOAT_PACKAGES = (
    "com.facebook.aloha.analytics",
    "com.facebook.aloha.app.messenger",
    "com.facebook.aloha.app.whatsapp",
    "com.facebook.aloha.app.portalfeed",
    "com.facebook.alohaapps.superframe",
    "com.facebook.alohaapps.contacts",
)
META_ACCOUNT_BACKUP_REMOTE = "/data/local/tmp/portal-meta-accounts-before-v1.tsv"
META_ACCOUNT_LOCAL_CLEAN_REMOTE = "/data/local/tmp/portal-meta-local-clean-v1"
META_ACCOUNT_TYPES = (
    "com.facebook.aloha.sso",
    "com.facebook.aloha.pl",
    "com.facebook.aloha.privowner",
)
META_AUTHENTICATOR_COMPONENTS = (
    "com.facebook.aloha.system.alohausers.services.AuthenticationService",
    "com.facebook.aloha.system.alohausers.services2.PLAuthenticatorService",
    "com.facebook.aloha.system.alohausers.services2."
    "PrivOwnerAccountsAuthenticatorService",
)
META_HARDWARE_AUTHENTICATOR = (
    "com.facebook.alohaservices.alohausers/"
    "com.facebook.aloha.system.alohausers.services2.HWAuthenticatorService"
)
SELF_MANAGED_DEBLOAT_COMPONENTS = frozenset(
    {
        "com.facebook.aloha.system.device/"
        "com.facebook.fbns.standalone.service.RegisteredMqttSystemBroadcastReceiver",
        "com.facebook.alohaservices.alohausers/com.facebook.mqttlite.MqttService",
    }
)

AdbRun = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclasses.dataclass(frozen=True)
class SettingsConfig:
    """The provisioner flag slice this cluster reads."""

    debloat: bool = False
    restore_bloat: bool = False
    block_remote_wipe: bool = False
    restore_remote_wipe: bool = False
    restore_meta_authenticators: bool = False
    privacy_dns: str | None = None
    dhcp_dns: bool = False
    restore_privacy_dns: bool = False


def parse_debloat_backup(contents: str) -> dict[str, str]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-debloat-backup-v1":
            raise ProvisionError("unrecognized Portal debloat backup format")
        states: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProvisionError(f"invalid Portal debloat backup line: {line!r}")
            package, state = fields
            if package in states or package not in DEBLOAT_PACKAGES:
                raise ProvisionError(
                    f"unexpected package in Portal debloat backup: {package!r}"
                )
            if state not in {"enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid state in Portal debloat backup: {state!r}"
                )
            states[package] = state
        missing = set(DEBLOAT_PACKAGES) - states.keys()
        if missing:
            raise ProvisionError(
                "Portal debloat backup is incomplete: " + ", ".join(sorted(missing))
            )
        return states

def parse_component_backup(contents: str) -> dict[str, tuple[str, str]]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-debloat-components-backup-v1":
            raise ProvisionError("unrecognized component debloat backup format")
        expected = {component: category for category, component in DEBLOAT_COMPONENTS}
        states: dict[str, tuple[str, str]] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 3:
                raise ProvisionError(f"invalid component backup line: {line!r}")
            category, component, state = fields
            if (
                component in states
                or component not in expected
                or expected[component] != category
            ):
                raise ProvisionError(
                    f"unexpected component in debloat backup: {component!r}"
                )
            if state not in {"default", "enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid component state in debloat backup: {state!r}"
                )
            states[component] = (category, state)
        missing = set(DEBLOAT_COMPONENT_NAMES) - states.keys()
        if missing:
            raise ProvisionError(
                "component debloat backup is incomplete: "
                + ", ".join(sorted(missing))
            )
        return states

def component_override_set(package_dump: str, label: str) -> set[str]:
        match = re.search(
            rf"(?m)^      {re.escape(label)}:\s*\n"
            r"((?:        \S[^\n]*\n)*)",
            package_dump,
        )
        if not match:
            return set()
        return {line.strip() for line in match.group(1).splitlines() if line.strip()}

def parse_remote_wipe_backup(contents: str) -> dict[str, str]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-remote-wipe-components-backup-v1":
            raise ProvisionError("unrecognized remote-wipe backup format")
        states: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProvisionError(f"invalid remote-wipe backup line: {line!r}")
            component, state = fields
            if component in states or component not in REMOTE_WIPE_COMPONENTS:
                raise ProvisionError(
                    f"unexpected component in remote-wipe backup: {component!r}"
                )
            if state not in {"default", "enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid state in remote-wipe backup: {state!r}"
                )
            states[component] = state
        missing = set(REMOTE_WIPE_COMPONENTS) - states.keys()
        if missing:
            raise ProvisionError(
                "remote-wipe backup is incomplete: " + ", ".join(sorted(missing))
            )
        return states

def restore_component_action(state: str) -> str:
        return (
            "default"
            if state == "default"
            else "enable"
            if state == "enabled"
            else "disable"
        )

class SettingsFeature:
    """Debloat / Meta accounts / remote-wipe / Private DNS host logic."""

    def __init__(
        self,
        *,
        adb_run: AdbRun,
        log_dir: pathlib.Path,
        target: Callable[[], "PortalTarget | None"],
        config: Callable[[], SettingsConfig],
        ensure_adb_framework_enabled: Callable[[], None],
        push_text_atomic: Callable[[str, str], None],
        settle_package_state: Callable[..., None],
        package_sets: Callable[[], "tuple[set[str], set[str]]"],
        current_component_states: Callable[[], "dict[str, tuple[str, str]]"],
        current_named_component_states: Callable[
            [tuple[str, ...]], "dict[str, str]"
        ],
        meta_accounts: Callable[[], "list[tuple[str, str]]"],
        disabled_meta_authenticators: Callable[[], "set[str]"],
        read_component_backup: Callable[
            ..., "dict[str, tuple[str, str]] | None"
        ],
        read_remote_wipe_backup: Callable[..., "dict[str, str] | None"],
        ensure_remote_wipe_backup: Callable[[], "dict[str, str]"],
        alohausers_desired_disabled: Callable[[], bool] | None = None,
    ):
        self._adb_run = adb_run
        self._log_dir = log_dir
        self._target = target
        self._config_factory = config
        self._ensure_adb_framework_enabled = ensure_adb_framework_enabled
        self._push_text_atomic = push_text_atomic
        self._settle_package_state = settle_package_state
        self._package_sets = package_sets
        self._current_component_states = current_component_states
        self._current_named_component_states = current_named_component_states
        self._meta_accounts = meta_accounts
        self._disabled_meta_authenticators = disabled_meta_authenticators
        self._read_component_backup = read_component_backup
        self._read_remote_wipe_backup = read_remote_wipe_backup
        self._ensure_remote_wipe_backup = ensure_remote_wipe_backup
        self._alohausers_desired_disabled = (
            alohausers_desired_disabled or (lambda: False)
        )
        self.meta_accounts_absent = False
        self.meta_accounts_package_disabled = False

    @property
    def _config(self) -> SettingsConfig:
        # Late-bound: the provisioner builds a fresh SettingsConfig
        # from its current flag attributes on every access, so flag
        # mutations after construction (used by tests and by the
        # recover flow) are honored.
        return self._config_factory()

    def debloat_component_names(self) -> tuple[str, ...]:
            profile = self._target().debloat_component_profile if self._target() else "full"
            try:
                return DEBLOAT_COMPONENT_PROFILES[profile]
            except KeyError as exc:
                raise ProvisionError(
                    f"unknown debloat component profile for this target: {profile}"
                ) from exc

    def unexpected_disabled_debloat_components(
            self,
            saved: dict[str, tuple[str, str]],
            current: dict[str, tuple[str, str]],
        ) -> list[str]:
            target_components = set(self.debloat_component_names())
            return sorted(
                component
                for component, (_, original) in saved.items()
                if component not in target_components
                and original in {"default", "enabled"}
                and current[component][1] == "disabled"
            )

    def debloat_preflight(self) -> bool:
            installed, disabled = self._package_sets()
            packages_complete = all(
                package not in installed or package in disabled
                for package in DEBLOAT_PACKAGES
            )
            saved = self._read_component_backup(required=False)
            components_complete = False
            if saved is not None:
                current = self._current_component_states()
                unexpected = self.unexpected_disabled_debloat_components(
                    saved, current
                )
                if unexpected:
                    raise ProvisionError(
                        "this target has disabled components outside its validated "
                        "profile; restore the saved component states with "
                        "--restore-bloat before provisioning again "
                        f"(unexpected={len(unexpected)})"
                    )
                components_complete = all(
                    saved[component][1] == "absent"
                    or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                    or current[component][1] == "disabled"
                    for component in self.debloat_component_names()
                )
            complete = packages_complete and components_complete
            print(
                "DEBLOAT_PREFLIGHT "
                f"packages_complete={int(packages_complete)} "
                f"components_complete={int(components_complete)} "
                f"action={'skip' if complete else 'install'}"
            )
            return complete

    def meta_accounts(self) -> list[tuple[str, str]]:
            output = self._adb_run(
                ["shell", "dumpsys", "account"], timeout=20, check=True
            ).stdout
            accounts = re.findall(
                r"Account \{name=([^,}]+), type=([^}]+)\}", output
            )
            return [
                (name, account_type)
                for name, account_type in accounts
                if account_type in META_ACCOUNT_TYPES
            ]

    def disabled_meta_authenticators(self) -> set[str]:
            output = self._adb_run(
                ["shell", "dumpsys", "package", "com.facebook.alohaservices.alohausers"],
                timeout=20,
                check=True,
            ).stdout
            match = re.search(
                r"disabledComponents:\s*(.*?)(?:\n\s*\w[^:\n]*:|\Z)",
                output,
                re.DOTALL,
            )
            return set() if match is None else set(match.group(1).split())

    def alohausers_package_disabled(self) -> bool:
            output = self._adb_run(
                ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
            ).stdout
            return "package:com.facebook.alohaservices.alohausers" in output

    def meta_accounts_preflight(self) -> bool:
            # Meta's Debug page is tied to the owner profile and can become empty
            # after account cleanup. Keep Android's own ADB framework active so a
            # newly presented host key can still raise its confirmation dialog.
            self._ensure_adb_framework_enabled()
            accounts = self._meta_accounts()
            self.meta_accounts_absent = not accounts
            disabled = self._disabled_meta_authenticators()
            self.meta_accounts_package_disabled = (
                self.alohausers_package_disabled()
            )
            hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
            already_clean = (
                not accounts
                and set(META_AUTHENTICATOR_COMPONENTS) <= disabled
                and hardware_class not in disabled
                and not self.meta_accounts_package_disabled
            )
            existing = self._adb_run(
                ["shell", "cat", META_ACCOUNT_BACKUP_REMOTE], timeout=5
            )
            if existing.returncode != 0:
                contents = "# portal-meta-accounts-before-v1\n" + "".join(
                    f"{account_type}\t{name}\n" for name, account_type in accounts
                )
                with tempfile.TemporaryDirectory(prefix="portal-meta-accounts-") as tmp:
                    local = pathlib.Path(tmp) / "accounts.tsv"
                    local.write_text(contents, encoding="utf-8")
                    self._adb_run(
                        ["push", str(local), META_ACCOUNT_BACKUP_REMOTE],
                        timeout=15,
                        check=True,
                    )
                self._adb_run(
                    ["shell", "chmod", "0600", META_ACCOUNT_BACKUP_REMOTE],
                    timeout=5,
                    check=True,
                )
            else:
                contents = existing.stdout
            host_backup = self._log_dir / "meta-accounts-before.tsv"
            if not host_backup.exists():
                host_backup.write_text(contents, encoding="utf-8")
                host_backup.chmod(0o600)
            print(
                f"META_ACCOUNT_PREFLIGHT accounts={len(accounts)} "
                f"authenticators_disabled={len(disabled & set(META_AUTHENTICATOR_COMPONENTS))} "
                f"already_clean={int(already_clean)} backup={META_ACCOUNT_BACKUP_REMOTE}"
            )
            return already_clean

    def backup_private_dns(self) -> None:
            existing = self._adb_run(["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5)
            if existing.returncode != 0:
                backup = {
                    "schema": 1,
                    "mode": self._adb_run(
                        ["shell", "settings", "get", "global", "private_dns_mode"],
                        timeout=5,
                        check=True,
                    ).stdout.strip(),
                    "hostname": self._adb_run(
                        [
                            "shell",
                            "settings",
                            "get",
                            "global",
                            "private_dns_specifier",
                        ],
                        timeout=5,
                        check=True,
                    ).stdout.strip(),
                }
                with tempfile.TemporaryDirectory(prefix="portal-private-dns-") as temp:
                    local = pathlib.Path(temp) / "private-dns.json"
                    local.write_text(json.dumps(backup, indent=2) + "\n")
                    self._adb_run(
                        ["push", str(local), PRIVACY_BACKUP_REMOTE],
                        timeout=15,
                        check=True,
                    )
                self._adb_run(
                    ["shell", "chmod", "0600", PRIVACY_BACKUP_REMOTE],
                    timeout=5,
                    check=True,
                )

    def apply_privacy_dns(self) -> None:
            if not self._config.privacy_dns:
                return
            hostname = self._config.privacy_dns.strip().lower()
            if not re.fullmatch(
                r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                hostname,
            ):
                raise ProvisionError(f"invalid Private DNS hostname: {self._config.privacy_dns!r}")
            self.backup_private_dns()
            self._adb_run(
                ["shell", "settings", "put", "global", "private_dns_mode", "hostname"],
                timeout=10,
                check=True,
            )
            self._adb_run(
                [
                    "shell",
                    "settings",
                    "put",
                    "global",
                    "private_dns_specifier",
                    hostname,
                ],
                timeout=10,
                check=True,
            )
            # No write-back of the normalized hostname: the config is
            # a frozen snapshot rebuilt from the provisioner's flags
            # on every access, and verify_privacy_dns derives the same
            # normalized expectation from it.
            self.verify_privacy_dns()

    def apply_dhcp_dns(self) -> None:
            self.backup_private_dns()
            self._adb_run(
                ["shell", "settings", "put", "global", "private_dns_mode", "off"],
                timeout=10,
                check=True,
            )
            self._adb_run(
                ["shell", "settings", "delete", "global", "private_dns_specifier"],
                timeout=10,
                check=True,
            )
            self.verify_privacy_dns()

    def restore_private_dns(self) -> None:
            result = self._adb_run(
                ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
            )
            try:
                backup = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
            if not isinstance(backup, dict) or backup.get("schema") != 1:
                raise ProvisionError("unrecognized Private DNS backup")
            for key, setting in (
                ("mode", "private_dns_mode"),
                ("hostname", "private_dns_specifier"),
            ):
                value = backup.get(key)
                if not isinstance(value, str):
                    raise ProvisionError("Private DNS backup is incomplete")
                action = "delete" if value in {"", "null"} else "put"
                command = ["shell", "settings", action, "global", setting]
                if action == "put":
                    command.append(value)
                self._adb_run(command, timeout=10, check=True)
            print("PRIVACY_DNS_RESTORE_OK")

    def verify_privacy_dns(self) -> None:
            mode = self._adb_run(
                ["shell", "settings", "get", "global", "private_dns_mode"],
                timeout=5,
                check=True,
            ).stdout.strip()
            hostname = self._adb_run(
                ["shell", "settings", "get", "global", "private_dns_specifier"],
                timeout=5,
                check=True,
            ).stdout.strip()
            expected_mode = "hostname"
            expected_hostname = self._config.privacy_dns
            if expected_hostname is not None:
                # The applies write the normalized form to the device
                # (and the recorded-state derivation normalizes the
                # same way), so the expectation is normalized too
                # rather than read back from a mutated config.
                expected_hostname = expected_hostname.strip().lower()
            if self._config.dhcp_dns:
                expected_mode = "off"
                expected_hostname = "null"
            elif self._config.restore_privacy_dns:
                result = self._adb_run(
                    ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
                )
                try:
                    backup = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
                if not isinstance(backup, dict) or backup.get("schema") != 1:
                    raise ProvisionError("unrecognized Private DNS backup")
                expected_mode = backup.get("mode")
                expected_hostname = backup.get("hostname")
                if not isinstance(expected_mode, str) or not isinstance(
                    expected_hostname, str
                ):
                    raise ProvisionError("Private DNS backup is incomplete")
                if expected_mode in {"", "null"}:
                    expected_mode = "null"
                if expected_hostname in {"", "null"}:
                    expected_hostname = "null"
            if mode != expected_mode or hostname != expected_hostname:
                raise ProvisionError(
                    "Private DNS did not persist: "
                    f"mode={mode!r}/{expected_mode!r} "
                    f"hostname={hostname!r}/{expected_hostname!r}"
                )
            action = (
                "network"
                if self._config.dhcp_dns
                else "restored"
                if self._config.restore_privacy_dns
                else "strict"
            )
            print(f"PRIVACY_DNS_OK action={action} mode={mode} hostname={hostname}")

    def read_private_dns_state(self) -> tuple[str, str]:
            mode = self._adb_run(
                ["shell", "settings", "get", "global", "private_dns_mode"],
                timeout=5,
                check=True,
            ).stdout.strip()
            hostname = self._adb_run(
                [
                    "shell",
                    "settings",
                    "get",
                    "global",
                    "private_dns_specifier",
                ],
                timeout=5,
                check=True,
            ).stdout.strip()
            return mode, hostname

    def write_private_dns_state(self, mode: str, hostname: str) -> None:
            # The recorded-state repair write: same backup-first
            # discipline as the applies, then each field is put or
            # deleted to match the target value exactly ("null"/""
            # means the setting is absent).
            self.backup_private_dns()
            for setting, value in (
                ("private_dns_mode", mode),
                ("private_dns_specifier", hostname),
            ):
                if value in ("", "null"):
                    self._adb_run(
                        ["shell", "settings", "delete", "global", setting],
                        timeout=10,
                        check=True,
                    )
                else:
                    self._adb_run(
                        ["shell", "settings", "put", "global", setting, value],
                        timeout=10,
                        check=True,
                    )

    def read_private_dns_backup(self) -> dict[str, object] | None:
            # Non-raising backup read for the recorded-state check:
            # an absent or unreadable backup means the recorded end
            # state cannot be determined, never that it is stock.
            result = self._adb_run(
                ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5
            )
            if result.returncode != 0:
                return None
            try:
                backup = json.loads(result.stdout)
            except json.JSONDecodeError:
                return None
            if not isinstance(backup, dict) or backup.get("schema") != 1:
                return None
            return backup

    def package_sets(self) -> tuple[set[str], set[str]]:
            installed_result = self._adb_run(
                ["shell", "pm", "list", "packages"], timeout=15, check=True
            )
            disabled_result = self._adb_run(
                ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
            )

            def parse(output: str) -> set[str]:
                return {
                    line.removeprefix("package:").strip()
                    for line in output.splitlines()
                    if line.startswith("package:")
                }

            return parse(installed_result.stdout), parse(disabled_result.stdout)

    def read_debloat_backup(self, required: bool = True) -> dict[str, str] | None:
            result = self._adb_run(
                ["shell", "cat", DEBLOAT_BACKUP_REMOTE], timeout=5
            )
            if result.returncode != 0:
                if required:
                    raise ProvisionError(
                        f"debloat backup is absent: {DEBLOAT_BACKUP_REMOTE}"
                    )
                return None
            return parse_debloat_backup(result.stdout)

    def ensure_debloat_backup(self) -> dict[str, str]:
            existing = self.read_debloat_backup(required=False)
            if existing is not None:
                print(f"DEBLOAT_BACKUP_OK existing=1 path={DEBLOAT_BACKUP_REMOTE}")
                return existing

            installed, disabled = self._package_sets()
            states = {
                package: (
                    "absent"
                    if package not in installed
                    else "disabled"
                    if package in disabled
                    else "enabled"
                )
                for package in DEBLOAT_PACKAGES
            }
            contents = "# portal-debloat-backup-v1\n" + "".join(
                f"{package}\t{states[package]}\n" for package in DEBLOAT_PACKAGES
            )
            remote_tmp = DEBLOAT_BACKUP_REMOTE + ".tmp"
            with tempfile.TemporaryDirectory(prefix="portal-debloat-") as temporary:
                local = pathlib.Path(temporary) / "backup.tsv"
                local.write_text(contents, encoding="utf-8")
                self._adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
            command = (
                f"chmod 0600 {shlex.quote(remote_tmp)} && "
                f"mv {shlex.quote(remote_tmp)} {shlex.quote(DEBLOAT_BACKUP_REMOTE)}"
            )
            self._adb_run(["shell", command], timeout=10, check=True)
            saved = self.read_debloat_backup(required=True)
            if saved != states:
                raise ProvisionError("debloat backup verification failed after write")
            print(f"DEBLOAT_BACKUP_OK existing=0 path={DEBLOAT_BACKUP_REMOTE}")
            return states

    def read_component_backup(
            self, required: bool = True
        ) -> dict[str, tuple[str, str]] | None:
            result = self._adb_run(
                ["shell", "cat", DEBLOAT_COMPONENT_BACKUP_REMOTE], timeout=10
            )
            if result.returncode != 0:
                if required:
                    raise ProvisionError(
                        "component debloat backup is absent: "
                        + DEBLOAT_COMPONENT_BACKUP_REMOTE
                    )
                return None
            return parse_component_backup(result.stdout)

    def current_named_component_states(
            self, components: tuple[str, ...], detect_missing: bool = False
        ) -> dict[str, str]:
            installed, _ = self._package_sets()
            by_package: dict[str, list[str]] = collections.defaultdict(list)
            for component in components:
                package, class_name = component.split("/", 1)
                by_package[package].append(class_name)
            states: dict[str, str] = {}
            for package, entries in by_package.items():
                if package not in installed:
                    for class_name in entries:
                        states[f"{package}/{class_name}"] = "absent"
                    continue
                dump = self._adb_run(
                    ["shell", "dumpsys", "package", package], timeout=20, check=True
                ).stdout
                enabled = component_override_set(dump, "enabledComponents")
                disabled = component_override_set(dump, "disabledComponents")
                for class_name in entries:
                    state = (
                        "enabled"
                        if class_name in enabled
                        else "disabled"
                        if class_name in disabled
                        else "absent"
                        if detect_missing and class_name not in dump
                        else "default"
                    )
                    states[f"{package}/{class_name}"] = state
            return states

    def current_component_states(self) -> dict[str, tuple[str, str]]:
            categories = {
                component: category for category, component in DEBLOAT_COMPONENTS
            }
            states = self._current_named_component_states(DEBLOAT_COMPONENT_NAMES)
            return {
                component: (categories[component], state)
                for component, state in states.items()
            }

    def ensure_component_backup(self) -> dict[str, tuple[str, str]]:
            existing = self._read_component_backup(required=False)
            if existing is not None:
                print(
                    "DEBLOAT_COMPONENT_BACKUP_OK existing=1 path="
                    + DEBLOAT_COMPONENT_BACKUP_REMOTE
                )
                return existing
            states = self._current_component_states()
            contents = "# portal-debloat-components-backup-v1\n" + "".join(
                f"{states[component][0]}\t{component}\t{states[component][1]}\n"
                for component in DEBLOAT_COMPONENT_NAMES
            )
            self._push_text_atomic(contents, DEBLOAT_COMPONENT_BACKUP_REMOTE)
            saved = self._read_component_backup(required=True)
            if saved != states:
                raise ProvisionError("component debloat backup verification failed")
            print(
                "DEBLOAT_COMPONENT_BACKUP_OK existing=0 path="
                + DEBLOAT_COMPONENT_BACKUP_REMOTE
            )
            return states

    def read_remote_wipe_backup(
            self, required: bool = True
        ) -> dict[str, str] | None:
            result = self._adb_run(
                ["shell", "cat", REMOTE_WIPE_BACKUP_REMOTE], timeout=5
            )
            if result.returncode != 0:
                if required:
                    raise ProvisionError(
                        f"remote-wipe backup is absent: {REMOTE_WIPE_BACKUP_REMOTE}"
                    )
                return None
            return parse_remote_wipe_backup(result.stdout)

    def ensure_remote_wipe_backup(self) -> dict[str, str]:
            existing = self._read_remote_wipe_backup(required=False)
            if existing is not None:
                print(
                    "REMOTE_WIPE_BACKUP_OK existing=1 path="
                    + REMOTE_WIPE_BACKUP_REMOTE
                )
                return existing
            states = self._current_named_component_states(
                REMOTE_WIPE_COMPONENTS, detect_missing=True
            )
            contents = "# portal-remote-wipe-components-backup-v1\n" + "".join(
                f"{component}\t{states[component]}\n"
                for component in REMOTE_WIPE_COMPONENTS
            )
            self._push_text_atomic(contents, REMOTE_WIPE_BACKUP_REMOTE)
            saved = self._read_remote_wipe_backup(required=True)
            if saved != states:
                raise ProvisionError("remote-wipe backup verification failed")
            print(
                "REMOTE_WIPE_BACKUP_OK existing=0 path="
                + REMOTE_WIPE_BACKUP_REMOTE
            )
            return states

    def prepare_component_actions(self) -> None:
            actions: list[str] = []
            modes: list[str] = []
            if self._config.debloat or self._config.restore_bloat:
                states = self._read_component_backup(required=False)
                if states is None:
                    if self._config.debloat:
                        states = self.ensure_component_backup()
                    else:
                        print("DEBLOAT_COMPONENT_RESTORE legacy_backup=absent actions=0")
                if states is not None:
                    action_components = (
                        self.debloat_component_names()
                        if self._config.debloat
                        else DEBLOAT_COMPONENT_NAMES
                    )
                    for component in action_components:
                        _, state = states[component]
                        if state == "absent":
                            continue
                        if self._config.debloat and component in SELF_MANAGED_DEBLOAT_COMPONENTS:
                            continue
                        action = (
                            "disable"
                            if self._config.debloat
                            else restore_component_action(state)
                        )
                        actions.append(f"{action}\t{component}\n")
                    modes.append("debloat-disable" if self._config.debloat else "debloat-restore")
                    if self._config.debloat:
                        account_backup = self._adb_run(
                            ["shell", "test", "-f", META_ACCOUNT_BACKUP_REMOTE],
                            timeout=5,
                        )
                        if account_backup.returncode == 0:
                            actions.append(f"enable\t{META_HARDWARE_AUTHENTICATOR}\n")
            if self._config.block_remote_wipe or self._config.restore_remote_wipe:
                remote_states = (
                    self._ensure_remote_wipe_backup()
                    if self._config.block_remote_wipe
                    else self._read_remote_wipe_backup(required=True)
                )
                assert remote_states is not None
                for component in REMOTE_WIPE_COMPONENTS:
                    state = remote_states[component]
                    if state == "absent":
                        continue
                    action = (
                        "disable"
                        if self._config.block_remote_wipe
                        else restore_component_action(state)
                    )
                    actions.append(f"{action}\t{component}\n")
                modes.append(
                    "remote-wipe-disable"
                    if self._config.block_remote_wipe
                    else "remote-wipe-restore"
                )
            if self._config.restore_meta_authenticators:
                # Two-tier restore semantics: replay the state the
                # component backup recorded for each authenticator;
                # with no record, the factory default is enabled.
                # (The accounts themselves are not restored — only
                # the components --remove-meta-accounts disabled.)
                recorded = self._read_component_backup(required=False)
                for component in META_AUTHENTICATOR_COMPONENTS:
                    state = "enabled"
                    if recorded is not None and component in recorded:
                        _, state = recorded[component]
                    if state == "absent":
                        continue
                    actions.append(
                        f"{restore_component_action(state)}\t{component}\n"
                    )
                modes.append("meta-authenticators-restore")
            self._push_text_atomic(
                "# portal-debloat-component-actions-v1\n" + "".join(actions),
                DEBLOAT_COMPONENT_ACTIONS_REMOTE,
            )
            self._adb_run(
                ["shell", "chmod", "0644", DEBLOAT_COMPONENT_ACTIONS_REMOTE],
                timeout=5,
                check=True,
            )
            print(
                f"COMPONENT_ACTIONS modes={','.join(modes) or 'none'} "
                f"count={len(actions)}"
            )

    def apply_debloat(self) -> None:
            self.ensure_debloat_backup()
            self.ensure_component_backup()
            installed, _ = self._package_sets()
            for package in DEBLOAT_PACKAGES:
                if package not in installed:
                    print(f"DEBLOAT_SKIP package={package} reason=absent")
                    continue
                result = self._adb_run(
                    ["shell", "pm", "disable-user", "--user", "0", package],
                    timeout=15,
                )
                if result.returncode != 0:
                    raise ProvisionError(
                        f"failed to disable debloat package {package}: {result.stdout}"
                    )
                print(f"DEBLOAT_DISABLE package={package}")
            self._settle_package_state()
            self.verify_debloat(require_components=False)

    def restore_debloat(self) -> None:
            states = self.read_debloat_backup(required=True)
            assert states is not None
            installed, _ = self._package_sets()
            for package in DEBLOAT_PACKAGES:
                state = states[package]
                if state == "absent" or package not in installed:
                    print(
                        f"DEBLOAT_RESTORE_SKIP package={package} "
                        f"original_state={state}"
                    )
                    continue
                action = "enable" if state == "enabled" else "disable-user"
                command = ["shell", "pm", action, "--user", "0", package]
                result = self._adb_run(command, timeout=15)
                if result.returncode != 0:
                    raise ProvisionError(
                        f"failed to restore package {package} to {state}: {result.stdout}"
                    )
                print(f"DEBLOAT_RESTORE package={package} state={state}")
            self._settle_package_state()
            self.verify_debloat_restored(require_components=False)

    def verify_retained_platform(self, wait_seconds: int = 45) -> None:
            deadline = time.monotonic() + wait_seconds
            ai_pid = ""
            camera = ""
            webview = ""
            home = ""
            while time.monotonic() < deadline:
                ai_pid = self._adb_run(
                    ["shell", "pidof", "com.facebook.portal.aiservice"],
                    timeout=5,
                ).stdout.strip()
                camera = self._adb_run(
                    ["shell", "dumpsys", "media.camera"], timeout=15
                ).stdout
                webview = self._adb_run(
                    ["shell", "dumpsys", "webviewupdate"], timeout=15
                ).stdout
                home = self._adb_run(
                    [
                        "shell",
                        "cmd",
                        "package",
                        "resolve-activity",
                        "--brief",
                        "-a",
                        "android.intent.action.MAIN",
                        "-c",
                        "android.intent.category.HOME",
                    ],
                    timeout=10,
                ).stdout.strip()
                if (
                    ai_pid
                    and "Number of camera devices: 2" in camera
                    and "Current WebView package (name, version): "
                    "(com.facebook.portal.webview," in webview
                    and "/" in home
                ):
                    print(
                        f"DEBLOAT_PLATFORM_OK aiservice_pid={ai_pid} cameras=2 "
                        f"home={home.splitlines()[-1]}"
                    )
                    return
                time.sleep(2)
            raise ProvisionError(
                "retained Portal services did not become ready after package-state change: "
                f"aiservice_pid={ai_pid!r} cameras_2="
                f"{int('Number of camera devices: 2' in camera)} webview="
                f"{int('(com.facebook.portal.webview,' in webview)} home={home!r}"
            )

    def verify_debloat(self, require_components: bool = True) -> None:
            installed, disabled = self._package_sets()
            missing = [
                package
                for package in DEBLOAT_PACKAGES
                if package in installed and package not in disabled
            ]
            if missing:
                raise ProvisionError(
                    "debloat packages became enabled: " + ", ".join(missing)
                )
            component_count = 0
            categories: collections.Counter[str] = collections.Counter()
            if require_components:
                saved = self._read_component_backup(required=True)
                assert saved is not None
                current = self._current_component_states()
                target_components = self.debloat_component_names()
                component_mismatches = [
                    component
                    for component in target_components
                    if saved[component][1] != "absent"
                    and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
                    and current[component][1] != "disabled"
                ]
                if component_mismatches:
                    raise ProvisionError(
                        "Meta cloud components became enabled: "
                        + ", ".join(component_mismatches)
                    )
                for component in target_components:
                    category, original = saved[component]
                    if (
                        original != "absent"
                        and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
                    ):
                        component_count += 1
                        categories[category] += 1
                running = self._adb_run(
                    ["shell", "dumpsys", "activity", "services"],
                    timeout=25,
                    check=True,
                ).stdout
                forbidden = (
                    "com.facebook.mqtt.service.MqttServiceV2",
                    "com.facebook.multiusermqtt.MultiuserMqttService",
                    "com.facebook.push.mqtt.service.MqttPushHelperService",
                    "com.facebook.aloha.wifidiagnostic.WifiDiagnosticService",
                    "com.facebook.alohasdk.pushnotification.PushNotificationService",
                    "com.facebook.aloha.system.services.bugreporter.PillViewService",
                )
                active = [
                    name
                    for name in forbidden
                    if any(
                        component.endswith("/" + name)
                        for component in target_components
                    )
                    and name in running
                ]
                if active:
                    raise ProvisionError(
                        "disabled Meta cloud services are still running: "
                        + ", ".join(active)
                    )
            self.verify_retained_platform()
            category_summary = ",".join(
                f"{name}:{categories[name]}" for name in sorted(categories)
            )
            print(
                f"DEBLOAT_OK packages={len(set(DEBLOAT_PACKAGES) & installed)} "
                f"components={component_count} categories={category_summary or 'pending'}"
            )

    def verify_debloat_restored(self, require_components: bool = True) -> None:
            states = self.read_debloat_backup(required=True)
            assert states is not None
            installed, disabled = self._package_sets()
            mismatches = []
            for package, state in states.items():
                if state == "absent":
                    continue
                actual = "disabled" if package in disabled else "enabled"
                if package not in installed or actual != state:
                    mismatches.append(f"{package}={actual}, expected {state}")
            if mismatches:
                raise ProvisionError("debloat restore mismatch: " + "; ".join(mismatches))
            if require_components:
                saved_components = self._read_component_backup(required=False)
                if saved_components is not None:
                    current = self._current_component_states()
                    component_mismatches = [
                        f"{component}={current[component][1]}, expected {state}"
                        for component, (_, state) in saved_components.items()
                        if state != "absent" and current[component][1] != state
                    ]
                    if component_mismatches:
                        raise ProvisionError(
                            "component debloat restore mismatch: "
                            + "; ".join(component_mismatches)
                        )
            self.verify_retained_platform()
            print(
                "DEBLOAT_RESTORE_OK components="
                + ("verified" if require_components else "pending")
            )

    def verify_remote_wipe_blocked(self) -> None:
            saved = self._read_remote_wipe_backup(required=True)
            assert saved is not None
            current = self._current_named_component_states(
                REMOTE_WIPE_COMPONENTS, detect_missing=True
            )
            mismatches = [
                f"{component}={current[component]}"
                for component in saved
                if current[component] not in {"disabled", "absent"}
            ]
            if mismatches:
                raise ProvisionError(
                    "Meta remote-wipe receivers became enabled: "
                    + "; ".join(mismatches)
                )
            print(
                "REMOTE_WIPE_BLOCK_OK receivers_disabled="
                + str(sum(state == "disabled" for state in current.values()))
                + " receivers_absent="
                + str(sum(state == "absent" for state in current.values()))
            )

    def verify_remote_wipe_restored(self) -> None:
            saved = self._read_remote_wipe_backup(required=True)
            assert saved is not None
            current = self._current_named_component_states(
                REMOTE_WIPE_COMPONENTS, detect_missing=True
            )
            mismatches = [
                f"{component}={current[component]}, expected {state}"
                for component, state in saved.items()
                if state != "absent" and current[component] != state
            ]
            if mismatches:
                raise ProvisionError(
                    "remote-wipe receiver restore mismatch: "
                    + "; ".join(mismatches)
                )
            print("REMOTE_WIPE_RESTORE_OK receivers=verified")

    def verify_meta_accounts_removed(self) -> None:
            accounts = self._meta_accounts()
            if accounts:
                raise ProvisionError(
                    "Meta accounts remain: "
                    + ", ".join(f"{account_type}/{name}" for name, account_type in accounts)
                )
            disabled = self._disabled_meta_authenticators()
            missing = set(META_AUTHENTICATOR_COMPONENTS) - disabled
            if missing:
                raise ProvisionError(
                    "Meta authenticators became enabled: " + ", ".join(sorted(missing))
                )
            hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
            if hardware_class in disabled:
                raise ProvisionError(
                    "the required hardware-identity authenticator is disabled"
                )
            package_state = self._adb_run(
                ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
            ).stdout
            package_disabled = (
                "package:com.facebook.alohaservices.alohausers" in package_state
            )
            if package_disabled and self._alohausers_desired_disabled():
                # The recorded end state IS the disabled posture
                # (C3-A): the run started with the package disabled
                # and recorded that as the desired state, so the
                # disabled package is the pass condition here, not
                # a failure. The accounts and authenticator checks
                # above are unaffected - the posture never licenses
                # leftover accounts - and the retained-platform
                # check still runs.
                self.verify_retained_platform()
                print(
                    "META_ACCOUNTS_REMOVED_OK accounts=0 authenticators=disabled "
                    "alohausers=disabled-posture"
                )
                return
            if package_disabled:
                raise ProvisionError("alohausers package was disabled instead of its authenticators")
            self.verify_retained_platform()
            print(
                "META_ACCOUNTS_REMOVED_OK accounts=0 authenticators=disabled "
                "alohausers=enabled"
            )
