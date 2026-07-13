from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from app_policy.models import AppPolicy, AppPolicyAction, AppPolicyMode, AppPolicyRule
from app_policy.store import AppPolicyStore
from cli import color
from cli.ipc.client import WatchdogIPCClient
from cli.ipc.errors import WatchdogIPCError
from config.app_config import AppConfig
from config.backup_manager import (
    BACKUP_SENSITIVE_WARNING,
    BackupManager,
    INFORMATIONAL_SECTION_NAMES,
    MERGE_SECTION_NAMES,
    RESTORE_REPLACE_CONFIRMATION,
    SUPPORTED_SECTION_NAMES,
)
from config.dns_policy_store import DNSPolicyStore
from config.lan_sharing import (
    lan_sharing_credentials_path,
    load_or_create_lan_sharing_credentials,
)
from config.paths import resolve_config_dir
from config.persistence import PersistentStoreError, atomic_write_bytes, dump_json
from config.profile_store import ProfileStore
from config.provider_store import DuplicateProviderError, ProviderLimitError, ProviderStore
from config.state_manager import (
    ALLOWED_ACTIVE_MODES,
    ALLOWED_DEFAULT_ROUTE_ACTIONS,
    ALLOWED_ROUTING_POLICIES,
    CONNECTABLE_CAPTURE_MODE_SETS,
    StateManager,
    capture_modes_connectable,
    parse_capture_modes,
)
from dns.hijack import DNSHijackController, DNSHijackError
from dns.models import (
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    DNSRuleAction,
    Resolver,
    StaticIPEntry,
)
from dns.resolver_inventory import detect_resolver_manager
from dns.singbox import fakeip_policy_ready
from dns.state_manager import (
    DNSStateError,
    DNSStateSnapshot,
    LocalDNSEntryPoint,
    SystemDNSStateManager,
    load_snapshot,
    save_snapshot,
)
from dns.tester import DNSTester
from daemon.protocol import Response
from diagnostics.route_dns import RouteDNSDiagnostic, diagnose_route_dns
from diagnostics.chain_routes import ChainRouteDiagnostic, diagnose_chain_route_action
from diagnostics.routing import RouteDiagnostic, diagnose_route
from metrics.models import MetricsDocument, MetricsRedactionMode
from metrics.store import MetricsStore
from models.connection_state import FAILURE_STATUSES
from models.profile import Profile, ProfileSource, profile_fingerprint, profile_resilience_category
from models.provider import Provider, normalized_provider_url
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy, NodeGroupSelectionMode
from node_groups.store import NodeGroupStore, NodeGroupStoreError
from parsers import ParseError
from parsers import parse_uri, validate_subscription_url
from providers.manual_provider import ManualProvider
from providers.subscription_provider import ProviderNotFoundError, SubscriptionProvider
from rotation import pool_builder
from rules.explanation import (
    RuleExplanationConfidence,
)
from rules.importer import RuleImportError, build_rule_import_plan
from rules.models import ALLOWED_RULE_CONDITIONS, Rule, RuleGroup
from rules.rule_engine import TrafficInfo
from rules.rule_store import RuleStore, RuleStoreError
from rules.ruleset_lifecycle import (
    RuleSetLifecycleError,
    RuleSetLifecycleManager,
    referenced_rule_set_ids,
)
from rules.ruleset_trust import RuleSetFailureBehavior, RuleSetKind, RuleSetTrustPolicy
from rules.ruleset_trust_store import RuleSetTrustStore, RuleSetTrustStoreError
from route_chains.models import ChainHop, ChainHopType, RouteChain, chain_target
from route_chains.runtime import ChainRuntimeResolver
from route_chains.store import RouteChainStore


DEFAULT_DNS_SNAPSHOT_NAME = "dns-state.json"
CONFIG_SET_KEYS = frozenset(
    {
        "watchdog.check_interval_seconds",
        "rotation.scheduled_interval_hours",
        "rotation.test_url",
        "rotation.test_timeout_seconds",
        "rotation.latency_max_stale_seconds",
        "kill_switch.block_ipv6",
        "kill_switch.allow_lan",
        "kill_switch.tunnel_interface",
        "kill_switch.on_manual_disconnect",
        "lan_sharing.enabled",
        "lan_sharing.mode",
        "lan_sharing.bind_address",
        "lan_sharing.socks_port",
        "lan_sharing.http_port",
        "lan_sharing.authentication_required",
        "lan_sharing.firewall_managed",
        "lan_sharing.gateway_interface",
        "lan_sharing.gateway_client_cidr",
        "lan_sharing.gateway_dns_mode",
    }
)
CONFIG_INT_SET_KEYS = frozenset(
    {
        "watchdog.check_interval_seconds",
        "rotation.scheduled_interval_hours",
        "rotation.test_timeout_seconds",
        "rotation.latency_max_stale_seconds",
        "lan_sharing.socks_port",
        "lan_sharing.http_port",
    }
)
CONFIG_BOOL_SET_KEYS = frozenset(
    {
        "kill_switch.block_ipv6",
        "kill_switch.allow_lan",
        "lan_sharing.enabled",
        "lan_sharing.authentication_required",
        "lan_sharing.firewall_managed",
    }
)
DNS_POLICY_SET_KEYS = frozenset(
    {
        "dns.proxy_resolution_channel",
        "dns.fakeip_inet4_range",
        "dns.fakeip_inet6_range",
        "dns.ecs_direct_enabled",
        "dns.ecs_direct_subnet",
        "dns.resolve_inbound_domains",
        "dns.static_ip_enabled",
        "dns.rules_enabled",
        "dns.ttl",
        "dns.test_domain",
        "dns.tun_hijack",
    }
)
DNS_POLICY_BOOL_SET_KEYS = frozenset(
    {
        "dns.ecs_direct_enabled",
        "dns.resolve_inbound_domains",
        "dns.static_ip_enabled",
        "dns.rules_enabled",
        "dns.tun_hijack",
    }
)
VISIBLE_STATS_COUNTER_PREFIXES = (
    "command.",
    "rotation.",
    "health_check.status.",
    "recovery.status.",
    "node_group.",
    "error.",
    "profile.",
    "route_action.",
    "rule_group.",
)


ROOT_HELP = """WatchdogVPN — local network control plane for resilient VPN/proxy routing

Usage: watchdog <command> [options]

Core:
  connect       Connect through the WatchdogVPN daemon
  disconnect    Disconnect through the WatchdogVPN daemon
  status        Show daemon connection status
  rotate        Rotate connection through the WatchdogVPN daemon

Diagnostics:
  doctor        Run the repository doctor
  stats         Inspect local observability metrics
  version       Print WatchdogVPN version

Profiles and providers:
  profile       Manage local profiles
  provider      Manage external providers

Policy:
  dns           Manage DNS v2 policy and state
  rules         Inspect configured routing rules
  ruleset       Inspect and refresh trusted remote or built-in rule sets
  app-policy    Manage minimal Linux app/process policy
  node-group    Manage node groups
  config        Manage WatchdogVPN configuration

Maintenance:
  backup        Create, inspect and restore backups
  setup         Configure local WatchdogVPN defaults
  panic         Run the WatchdogVPN panic button
  uninstall     Run the safe WatchdogVPN uninstall flow

Examples:
  watchdog status
  watchdog doctor
  watchdog profile list
  watchdog dns status
  watchdog connect <profile-id>
  watchdog disconnect

Use: watchdog <command> --help
"""


def _root_help(*, no_color: bool = False) -> str:
    if not color.color_enabled(no_color=no_color):
        return ROOT_HELP
    lines: list[str] = []
    for line in ROOT_HELP.splitlines():
        stripped = line.strip()
        if stripped in {
            "Core:",
            "Diagnostics:",
            "Profiles and providers:",
            "Policy:",
            "Maintenance:",
            "Examples:",
        }:
            lines.append(color.style(line, "bold", no_color=no_color))
        elif stripped.startswith("watchdog "):
            lines.append(line.replace(stripped, color.command(stripped, no_color=no_color)))
        elif stripped == "Use: watchdog <command> --help":
            lines.append(line.replace("watchdog <command> --help", color.command("watchdog <command> --help", no_color=no_color)))
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


class _JSONAwareArgumentParser(argparse.ArgumentParser):
    """Emits a JSON error envelope on parse failure when --json was requested.

    argparse's own .error() runs before parsing finishes, so args.json
    isn't available yet - main() sets this class attribute from the raw
    argv right before parse_args() (WDCLI-009: previously argparse-level
    errors - missing args, bad choices - always printed plain text to
    stderr, ignoring --json entirely).
    """

    _json_requested = False

    def error(self, message: str) -> None:
        if _JSONAwareArgumentParser._json_requested:
            _print_json({"version": 1, "type": "response", "ok": False, "payload": {}, "error": message})
            self.exit(2)
        super().error(message)


class RootHelpArgumentParser(_JSONAwareArgumentParser):
    def format_help(self) -> str:
        return _root_help()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    parsed_argv = sys.argv[1:] if argv is None else list(argv)
    restore_no_color = None
    if "--no-color" in parsed_argv:
        restore_no_color = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
    _JSONAwareArgumentParser._json_requested = "--json" in parsed_argv
    try:
        args = parser.parse_args(parsed_argv)
    finally:
        _JSONAwareArgumentParser._json_requested = False
        if restore_no_color is None and "--no-color" in parsed_argv:
            os.environ.pop("NO_COLOR", None)
        elif restore_no_color is not None:
            os.environ["NO_COLOR"] = restore_no_color
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    as_json = bool(getattr(args, "json", False))
    try:
        return int(args.handler(args))
    except (DuplicateProviderError, ProviderLimitError, ProviderNotFoundError) as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except RuleStoreError as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except RuleSetLifecycleError as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except RuleSetTrustStoreError as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except NodeGroupStoreError as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except ParseError as exc:
        _error(str(exc), as_json=as_json)
        return 65
    except FileNotFoundError as exc:
        _error(str(exc), as_json=as_json)
        return 66
    except PersistentStoreError as exc:
        _error(str(exc), as_json=as_json)
        return 70
    except WatchdogIPCError as exc:
        _error(str(exc), as_json=as_json)
        return exc.exit_code
    except KeyboardInterrupt:
        _error("operation cancelled", as_json=as_json)
        return 130
    except (DNSHijackError, DNSStateError, OSError, ValueError) as exc:
        _error(str(exc), as_json=as_json)
        return 70


def _build_parser() -> argparse.ArgumentParser:
    parser = RootHelpArgumentParser(prog="watchdog", usage="<command> [options]")
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(
        dest="command",
        # Deliberately _JSONAwareArgumentParser, not RootHelpArgumentParser:
        # the latter's format_help() override is root-only and would break
        # every subcommand's own --help text if it propagated down here.
        parser_class=_JSONAwareArgumentParser,
    )

    connect_parser = subparsers.add_parser("connect", help="Connect through the WatchdogVPN daemon")
    connect_parser.add_argument("profile_id", help="Profile ID to connect")
    connect_parser.add_argument("--json", action="store_true", help="Print JSON")
    connect_parser.set_defaults(handler=_connection_connect)

    disconnect_parser = subparsers.add_parser("disconnect", help="Disconnect through the WatchdogVPN daemon")
    disconnect_parser.add_argument("--json", action="store_true", help="Print JSON")
    disconnect_parser.set_defaults(handler=_connection_disconnect)

    status_parser = subparsers.add_parser("status", help="Show daemon connection status")
    status_parser.add_argument("--json", action="store_true", help="Print JSON")
    status_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in human output")
    status_parser.set_defaults(handler=_connection_status)

    rotate_parser = subparsers.add_parser("rotate", help="Rotate connection through the WatchdogVPN daemon")
    rotate_parser.add_argument("--force", action="store_true", help="Force rotation even if conservative checks apply")
    rotate_parser.add_argument("--json", action="store_true", help="Print JSON")
    rotate_parser.set_defaults(handler=_connection_rotate)

    version_parser = subparsers.add_parser("version", help="Print WatchdogVPN version")
    version_parser.add_argument("--json", action="store_true", help="Print JSON")
    version_parser.add_argument("--version-source", help=argparse.SUPPRESS)
    version_parser.set_defaults(handler=_version)

    panic_parser = subparsers.add_parser("panic", help="Run the WatchdogVPN panic button")
    panic_parser.add_argument("mode", choices=["sleep", "wake", "status"], help="Panic mode")
    panic_parser.add_argument("--panic-script", help=argparse.SUPPRESS)
    panic_parser.set_defaults(handler=_panic)

    doctor_parser = subparsers.add_parser("doctor", help="Run the repository doctor")
    doctor_parser.add_argument("--json", action="store_true", help="Print JSON")
    doctor_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in human output")
    doctor_parser.add_argument("--doctor-script", help=argparse.SUPPRESS)
    doctor_parser.set_defaults(handler=_doctor)

    setup_parser = subparsers.add_parser("setup", help="Configure local WatchdogVPN defaults")
    setup_parser.add_argument("--dry-run", action="store_true", help="Show setup plan without writing local state")
    setup_parser.add_argument("--yes", action="store_true", help="Apply local setup changes")
    setup_parser.add_argument("--json", action="store_true", help="Print JSON")
    setup_parser.add_argument("--language", help="Set selected language, for example en or es")
    setup_parser.add_argument("--autostart", choices=["enable", "disable"], help="Set app autostart intent")
    setup_parser.add_argument("--autoconnect", choices=["enable", "disable"], help="Set VPN autoconnect intent")
    setup_parser.add_argument("--profile-uri", help="Import one local profile URI")
    setup_parser.add_argument("--provider-url", help="Store one provider subscription URL without refreshing it")
    setup_parser.add_argument("--provider-name", help="Provider label for --provider-url")
    setup_parser.add_argument("--kill-switch", choices=["enable", "disable"], help="Set kill switch policy")
    setup_parser.add_argument("--dns-mode", choices=[item.value for item in DNSMode], help="Set DNS policy mode")
    setup_parser.add_argument("--app-policy", choices=["enable", "disable"], help="Set app policy enabled state")
    setup_parser.add_argument(
        "--app-policy-mode",
        choices=[item.value for item in AppPolicyMode],
        help="Set app policy mode",
    )
    setup_parser.add_argument(
        "--app-policy-default-action",
        choices=[item.value for item in AppPolicyAction],
        help="Set app policy default action",
    )
    setup_parser.add_argument(
        "--acknowledge-backup-warning",
        action="store_true",
        help="Acknowledge that local setup changes should be backed up",
    )
    setup_parser.set_defaults(handler=_setup)

    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Run the safe WatchdogVPN uninstall flow",
    )
    uninstall_mode = uninstall_parser.add_mutually_exclusive_group()
    uninstall_mode.add_argument(
        "--keep-data",
        action="store_true",
        help="Uninstall product files and preserve local WatchdogVPN data",
    )
    uninstall_mode.add_argument(
        "--backup-first",
        action="store_true",
        help="Export a backup before uninstalling product files",
    )
    uninstall_mode.add_argument(
        "--delete-all-data",
        action="store_true",
        help="Export a pre-delete backup, then uninstall and purge WatchdogVPN data",
    )
    uninstall_parser.add_argument("--yes", action="store_true", help="Confirm product uninstall")
    uninstall_parser.add_argument("--dry-run", action="store_true", help="Show plan without changing the system")
    uninstall_parser.add_argument("--skip-dns-rescue", action="store_true", help="Skip uninstall DNS rescue")
    uninstall_parser.add_argument("--backup-output", help="Backup path for backup-first/delete-all-data")
    uninstall_parser.add_argument(
        "--encrypt-backup",
        action="store_true",
        help="Encrypt the backup using a password from --backup-password-env",
    )
    uninstall_parser.add_argument(
        "--backup-password-env",
        help="Environment variable containing the encrypted-backup password",
    )
    uninstall_parser.add_argument(
        "--confirm-delete",
        help="Required literal DELETE for --delete-all-data",
    )
    uninstall_parser.add_argument("--uninstall-script", help=argparse.SUPPRESS)
    uninstall_parser.add_argument("--json", action="store_true", help="Print JSON")
    uninstall_parser.set_defaults(handler=_uninstall)

    backup_parser = subparsers.add_parser("backup", help="Create, inspect and restore backups")
    backup_subparsers = backup_parser.add_subparsers(dest="backup_command")
    backup_subparsers.required = True

    backup_create_parser = backup_subparsers.add_parser("create", help="Create a backup archive")
    _add_backup_create_args(backup_create_parser)
    backup_create_parser.set_defaults(handler=_backup_create)

    backup_export_parser = backup_subparsers.add_parser("export", help="Alias for backup create")
    _add_backup_create_args(backup_export_parser)
    backup_export_parser.set_defaults(handler=_backup_create)

    backup_inspect_parser = backup_subparsers.add_parser("inspect", help="Inspect and validate a backup archive")
    backup_inspect_parser.add_argument("file")
    backup_inspect_parser.add_argument("--password-env", help="Environment variable containing the encrypted-backup password")
    backup_inspect_parser.add_argument("--json", action="store_true", help="Print JSON")
    backup_inspect_parser.set_defaults(handler=_backup_inspect)

    backup_restore_parser = backup_subparsers.add_parser("restore", help="Restore a backup archive")
    _add_backup_restore_args(backup_restore_parser)
    backup_restore_parser.set_defaults(handler=_backup_restore)

    backup_import_parser = backup_subparsers.add_parser("import", help="Alias for backup restore")
    _add_backup_restore_args(backup_import_parser)
    backup_import_parser.set_defaults(handler=_backup_restore)

    profile_parser = subparsers.add_parser("profile", help="Manage local profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")
    profile_subparsers.required = True

    add_parser = profile_subparsers.add_parser("add", help="Add a manual profile")
    add_source = add_parser.add_mutually_exclusive_group(required=True)
    add_source.add_argument("--clipboard", action="store_true", help="Read profile content from clipboard")
    add_source.add_argument("--uri", help="Import one profile URI")
    add_source.add_argument("--file", help="Import profile content from file")
    add_source.add_argument("--text", action="store_true", help="Read profile content from stdin or editor")
    add_parser.add_argument("--json", action="store_true", help="Print JSON")
    add_parser.set_defaults(handler=_profile_add)

    list_parser = profile_subparsers.add_parser("list", help="List saved profiles")
    list_parser.add_argument("--json", action="store_true", help="Print JSON")
    list_parser.add_argument("--pool", action="store_true", help="Show rotation pool only")
    list_parser.add_argument("--wide", action="store_true", help="Do not truncate profile IDs in human output")
    list_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in human output")
    list_parser.set_defaults(handler=_profile_list)

    remove_parser = profile_subparsers.add_parser("remove", help="Remove a saved profile")
    remove_parser.add_argument("profile_id")
    remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    remove_parser.set_defaults(handler=_profile_remove)

    enable_parser = profile_subparsers.add_parser("enable", help="Enable a saved profile")
    enable_parser.add_argument("profile_id")
    enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    enable_parser.set_defaults(handler=_profile_set_enabled)
    enable_parser.set_defaults(enabled=True)

    disable_parser = profile_subparsers.add_parser("disable", help="Disable a saved profile")
    disable_parser.add_argument("profile_id")
    disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    disable_parser.set_defaults(handler=_profile_set_enabled)
    disable_parser.set_defaults(enabled=False)

    rotation_parser = profile_subparsers.add_parser("rotation", help="Change profile rotation-pool membership")
    rotation_parser.add_argument("profile_id")
    rotation_group = rotation_parser.add_mutually_exclusive_group(required=True)
    rotation_group.add_argument("--enable", action="store_true", help="Add profile to rotation pool")
    rotation_group.add_argument("--disable", action="store_true", help="Remove profile from rotation pool")
    rotation_group.add_argument("--on", action="store_true", help="Alias for --enable")
    rotation_group.add_argument("--off", action="store_true", help="Alias for --disable")
    rotation_parser.add_argument("--json", action="store_true", help="Print JSON")
    rotation_parser.set_defaults(handler=_profile_rotation)

    provider_parser = subparsers.add_parser("provider", help="Manage external providers")
    provider_subparsers = provider_parser.add_subparsers(dest="provider_command")
    provider_subparsers.required = True

    provider_add_parser = provider_subparsers.add_parser("add", help="Add an external provider")
    provider_add_parser.add_argument("url", nargs="?", help="External provider subscription URL")
    provider_add_parser.add_argument("--name", help="Free-form provider label")
    provider_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_add_parser.set_defaults(handler=_provider_add)

    provider_list_parser = provider_subparsers.add_parser("list", help="List external providers")
    provider_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_list_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in human output")
    provider_list_parser.set_defaults(handler=_provider_list)

    provider_stats_parser = provider_subparsers.add_parser("stats", help="Show provider statistics")
    provider_stats_parser.add_argument("provider_id")
    provider_stats_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_stats_parser.set_defaults(handler=_provider_stats)

    provider_update_parser = provider_subparsers.add_parser("update", help="Update provider nodes")
    provider_update_target = provider_update_parser.add_mutually_exclusive_group(required=True)
    provider_update_target.add_argument("provider_id", nargs="?", help="Provider ID")
    provider_update_target.add_argument("--all", action="store_true", help="Update all providers")
    provider_update_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_update_parser.set_defaults(handler=_provider_update)

    provider_remove_parser = provider_subparsers.add_parser("remove", help="Remove provider and owned nodes")
    provider_remove_parser.add_argument("provider_id")
    provider_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_remove_parser.set_defaults(handler=_provider_remove)

    provider_edit_parser = provider_subparsers.add_parser(
        "edit", help="Edit provider name or subscription URL"
    )
    provider_edit_parser.add_argument("provider_id")
    provider_edit_parser.add_argument("--name", help="New free-form provider label")
    provider_edit_parser.add_argument("--url", help="New subscription URL")
    provider_edit_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_edit_parser.set_defaults(handler=_provider_edit)

    provider_rotation_parser = provider_subparsers.add_parser("rotation", help="Enable or disable provider rotation")
    provider_rotation_parser.add_argument("provider_id")
    provider_rotation_group = provider_rotation_parser.add_mutually_exclusive_group(required=True)
    provider_rotation_group.add_argument("--enable", action="store_true", help="Enable provider rotation")
    provider_rotation_group.add_argument("--disable", action="store_true", help="Disable provider rotation")
    provider_rotation_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_rotation_parser.set_defaults(handler=_provider_rotation)

    provider_node_parser = provider_subparsers.add_parser("node", help="Change provider node settings")
    provider_node_parser.add_argument("provider_id")
    provider_node_parser.add_argument("node_id")
    provider_node_parser.add_argument("--rotation", action="store_true", required=True)
    provider_node_group = provider_node_parser.add_mutually_exclusive_group(required=True)
    provider_node_group.add_argument("--enable", action="store_true", help="Enable node rotation")
    provider_node_group.add_argument("--disable", action="store_true", help="Disable node rotation")
    provider_node_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_node_parser.set_defaults(handler=_provider_node)

    node_group_parser = subparsers.add_parser("node-group", help="Manage node groups")
    node_group_subparsers = node_group_parser.add_subparsers(dest="node_group_command")
    node_group_subparsers.required = True

    node_group_list_parser = node_group_subparsers.add_parser("list", help="List node groups")
    node_group_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_list_parser.set_defaults(handler=_node_group_list)

    node_group_create_parser = node_group_subparsers.add_parser("create", help="Create a node group")
    node_group_create_parser.add_argument("name")
    node_group_create_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_create_parser.set_defaults(handler=_node_group_create)

    node_group_add_profile_parser = node_group_subparsers.add_parser(
        "add-profile", help="Add a profile to a node group"
    )
    node_group_add_profile_parser.add_argument("group")
    node_group_add_profile_parser.add_argument("profile")
    node_group_add_profile_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_add_profile_parser.set_defaults(handler=_node_group_add_profile)

    node_group_auto_test_parser = node_group_subparsers.add_parser(
        "auto-test", help="Measure and rank a node group's eligible candidates"
    )
    node_group_auto_test_parser.add_argument("group")
    node_group_auto_test_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_auto_test_parser.set_defaults(handler=_node_group_auto_test)

    node_group_select_parser = node_group_subparsers.add_parser(
        "select", help="Set a node group to auto mode or pin one profile"
    )
    node_group_select_parser.add_argument("group")
    node_group_select_parser.add_argument("selection", help="Profile ID or 'auto'")
    node_group_select_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_select_parser.set_defaults(handler=_node_group_select)

    node_group_add_provider_parser = node_group_subparsers.add_parser(
        "add-provider", help="Add a provider to a node group"
    )
    node_group_add_provider_parser.add_argument("group")
    node_group_add_provider_parser.add_argument("provider")
    node_group_add_provider_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_add_provider_parser.set_defaults(handler=_node_group_add_provider)

    node_group_remove_provider_parser = node_group_subparsers.add_parser(
        "remove-provider", help="Remove a provider from a node group"
    )
    node_group_remove_provider_parser.add_argument("group")
    node_group_remove_provider_parser.add_argument("provider")
    node_group_remove_provider_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_remove_provider_parser.set_defaults(handler=_node_group_remove_provider)

    node_group_exclude_parser = node_group_subparsers.add_parser(
        "exclude", help="Exclude a profile from a node group's candidates"
    )
    node_group_exclude_parser.add_argument("group")
    node_group_exclude_parser.add_argument("profile")
    node_group_exclude_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_exclude_parser.set_defaults(handler=_node_group_exclude)

    node_group_unexclude_parser = node_group_subparsers.add_parser(
        "unexclude", help="Remove a profile from a node group's exclusion list"
    )
    node_group_unexclude_parser.add_argument("group")
    node_group_unexclude_parser.add_argument("profile")
    node_group_unexclude_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_unexclude_parser.set_defaults(handler=_node_group_unexclude)

    node_group_resilience_parser = node_group_subparsers.add_parser(
        "resilience", help="Set a node group's resilience policy"
    )
    node_group_resilience_parser.add_argument("group")
    node_group_resilience_parser.add_argument(
        "policy", choices=[item.value for item in NodeGroupResiliencePolicy]
    )
    node_group_resilience_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_resilience_parser.set_defaults(handler=_node_group_set_resilience)

    node_group_enable_parser = node_group_subparsers.add_parser("enable", help="Enable a node group")
    node_group_enable_parser.add_argument("group")
    node_group_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_enable_parser.set_defaults(handler=_node_group_set_enabled, enabled=True)

    node_group_disable_parser = node_group_subparsers.add_parser("disable", help="Disable a node group")
    node_group_disable_parser.add_argument("group")
    node_group_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_disable_parser.set_defaults(handler=_node_group_set_enabled, enabled=False)

    dns_parser = subparsers.add_parser("dns", help="Manage DNS v2 policy and state")
    dns_subparsers = dns_parser.add_subparsers(dest="dns_command")
    dns_subparsers.required = True

    dns_status_parser = dns_subparsers.add_parser("status", help="Show DNS v2 status")
    _add_dns_common_paths(dns_status_parser)
    dns_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_status_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in human output")
    dns_status_parser.set_defaults(handler=_dns_status)

    dns_test_parser = dns_subparsers.add_parser("test", help="Test DNS v2 resolvers")
    _add_dns_common_paths(dns_test_parser, include_resolv_conf=False, include_snapshot=False)
    dns_test_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_test_parser.add_argument("--auto", action="store_true", help="Test default auto setup candidates")
    dns_test_parser.add_argument("--domain", help="Override the policy test domain")
    dns_test_parser.add_argument("--timeout", type=float, default=3.0, help="Resolver probe timeout in seconds")
    dns_test_parser.set_defaults(handler=_dns_test)

    dns_diagnose_parser = dns_subparsers.add_parser(
        "diagnose",
        help="Explain route and DNS policy for hypothetical traffic",
    )
    _add_dns_common_paths(dns_diagnose_parser, include_resolv_conf=False, include_snapshot=False)
    dns_diagnose_parser.add_argument("--domain", help="Traffic domain name")
    dns_diagnose_parser.add_argument("--ip", help="Traffic destination IP")
    dns_diagnose_parser.add_argument("--port", type=int, help="Traffic destination port")
    dns_diagnose_parser.add_argument("--protocol", help="Traffic protocol, for example tls")
    dns_diagnose_parser.add_argument("--network", help="Network transport, for example tcp")
    dns_diagnose_parser.add_argument("--process-name", help="Process executable name")
    dns_diagnose_parser.add_argument("--process-path", help="Exact process executable path")
    dns_diagnose_parser.add_argument("--ruleset-trust-file", help="Rule-set trust registry JSON file")
    dns_diagnose_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_diagnose_parser.set_defaults(handler=_dns_diagnose)

    dns_apply_parser = dns_subparsers.add_parser("apply", help="Apply DNS v2 local entrypoint")
    _add_dns_common_paths(dns_apply_parser)
    dns_apply_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_apply_parser.add_argument("--dry-run", action="store_true", help="Print the apply plan without changing DNS")
    dns_apply_parser.add_argument("--yes", action="store_true", help="Confirm system DNS mutation")
    dns_apply_parser.add_argument("--systemd-link", help="systemd-resolved link name, for example tun0")
    dns_apply_parser.add_argument("--entrypoint-address", default="127.0.0.1", help="Local DNS entrypoint address")
    dns_apply_parser.add_argument("--entrypoint-port", type=int, default=53, help="Local DNS entrypoint port")
    dns_apply_parser.add_argument(
        "--skip-entrypoint-check",
        action="store_true",
        help="Skip local DNS entrypoint reachability check",
    )
    dns_apply_parser.add_argument(
        "--entrypoint-timeout",
        type=float,
        default=1.0,
        help="Local DNS entrypoint TCP check timeout in seconds",
    )
    dns_apply_parser.set_defaults(handler=_dns_apply)

    dns_reset_parser = dns_subparsers.add_parser("reset", help="Restore DNS from the saved v2 snapshot")
    _add_dns_common_paths(dns_reset_parser)
    dns_reset_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_reset_parser.add_argument("--yes", action="store_true", help="Confirm DNS restore")
    dns_reset_parser.set_defaults(handler=_dns_reset)

    dns_channel_parser = dns_subparsers.add_parser("channel", help="Manage DNS channels")
    dns_channel_subparsers = dns_channel_parser.add_subparsers(dest="dns_channel_command")
    dns_channel_subparsers.required = True

    dns_channel_add_parser = dns_channel_subparsers.add_parser(
        "add", help="Add an empty DNS channel"
    )
    dns_channel_add_parser.add_argument("name", choices=[item.value for item in DNSChannelName])
    _add_dns_common_paths(dns_channel_add_parser, include_resolv_conf=False, include_snapshot=False)
    dns_channel_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_channel_add_parser.set_defaults(handler=_dns_channel_add)

    dns_channel_remove_parser = dns_channel_subparsers.add_parser(
        "remove", help="Remove a DNS channel and its resolvers"
    )
    dns_channel_remove_parser.add_argument("name", choices=[item.value for item in DNSChannelName])
    _add_dns_common_paths(dns_channel_remove_parser, include_resolv_conf=False, include_snapshot=False)
    dns_channel_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_channel_remove_parser.set_defaults(handler=_dns_channel_remove)

    dns_resolver_parser = dns_subparsers.add_parser("resolver", help="Manage DNS resolvers")
    dns_resolver_subparsers = dns_resolver_parser.add_subparsers(dest="dns_resolver_command")
    dns_resolver_subparsers.required = True

    dns_resolver_add_parser = dns_resolver_subparsers.add_parser(
        "add", help="Add a resolver to a DNS channel"
    )
    dns_resolver_add_parser.add_argument("channel", choices=[item.value for item in DNSChannelName])
    dns_resolver_add_parser.add_argument("uri", help="Resolver URI, for example udp://1.1.1.1")
    dns_resolver_add_parser.add_argument("--label", help="Free-form resolver label")
    dns_resolver_add_parser.add_argument(
        "--strategy",
        choices=["auto"],
        default="auto",
        help="Channel resolver strategy",
    )
    dns_resolver_add_parser.add_argument(
        "--disabled", action="store_true", help="Add the resolver disabled"
    )
    _add_dns_common_paths(dns_resolver_add_parser, include_resolv_conf=False, include_snapshot=False)
    dns_resolver_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_resolver_add_parser.set_defaults(handler=_dns_resolver_add)

    dns_resolver_remove_parser = dns_resolver_subparsers.add_parser(
        "remove", help="Remove a resolver from a DNS channel"
    )
    dns_resolver_remove_parser.add_argument("channel", choices=[item.value for item in DNSChannelName])
    dns_resolver_remove_parser.add_argument("uri")
    _add_dns_common_paths(dns_resolver_remove_parser, include_resolv_conf=False, include_snapshot=False)
    dns_resolver_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_resolver_remove_parser.set_defaults(handler=_dns_resolver_remove)

    dns_resolver_enable_parser = dns_resolver_subparsers.add_parser(
        "enable", help="Enable a resolver in a DNS channel"
    )
    dns_resolver_enable_parser.add_argument("channel", choices=[item.value for item in DNSChannelName])
    dns_resolver_enable_parser.add_argument("uri")
    _add_dns_common_paths(dns_resolver_enable_parser, include_resolv_conf=False, include_snapshot=False)
    dns_resolver_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_resolver_enable_parser.set_defaults(handler=_dns_resolver_set_enabled, enabled=True)

    dns_resolver_disable_parser = dns_resolver_subparsers.add_parser(
        "disable", help="Disable a resolver in a DNS channel"
    )
    dns_resolver_disable_parser.add_argument("channel", choices=[item.value for item in DNSChannelName])
    dns_resolver_disable_parser.add_argument("uri")
    _add_dns_common_paths(dns_resolver_disable_parser, include_resolv_conf=False, include_snapshot=False)
    dns_resolver_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_resolver_disable_parser.set_defaults(handler=_dns_resolver_set_enabled, enabled=False)

    dns_rule_parser = dns_subparsers.add_parser("rule", help="Manage DNS diversion rules")
    dns_rule_subparsers = dns_rule_parser.add_subparsers(dest="dns_rule_command")
    dns_rule_subparsers.required = True

    dns_rule_add_parser = dns_rule_subparsers.add_parser("add", help="Add a DNS diversion rule")
    dns_rule_add_parser.add_argument("id")
    dns_rule_add_parser.add_argument(
        "--pattern", required=True, help="For example domain:example.com or suffix:example.com"
    )
    dns_rule_add_parser.add_argument(
        "--action", required=True, choices=[item.value for item in DNSRuleAction]
    )
    dns_rule_add_parser.add_argument(
        "--channel", choices=[item.value for item in DNSChannelName], help="Required for --action use_channel"
    )
    dns_rule_add_parser.add_argument("--priority", type=int, default=100)
    dns_rule_add_parser.add_argument(
        "--disabled", action="store_true", help="Add the rule disabled"
    )
    _add_dns_common_paths(dns_rule_add_parser, include_resolv_conf=False, include_snapshot=False)
    dns_rule_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_rule_add_parser.set_defaults(handler=_dns_rule_add)

    dns_rule_remove_parser = dns_rule_subparsers.add_parser("remove", help="Remove a DNS diversion rule")
    dns_rule_remove_parser.add_argument("id")
    _add_dns_common_paths(dns_rule_remove_parser, include_resolv_conf=False, include_snapshot=False)
    dns_rule_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_rule_remove_parser.set_defaults(handler=_dns_rule_remove)

    dns_rule_enable_parser = dns_rule_subparsers.add_parser("enable", help="Enable a DNS diversion rule")
    dns_rule_enable_parser.add_argument("id")
    _add_dns_common_paths(dns_rule_enable_parser, include_resolv_conf=False, include_snapshot=False)
    dns_rule_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_rule_enable_parser.set_defaults(handler=_dns_rule_set_enabled, enabled=True)

    dns_rule_disable_parser = dns_rule_subparsers.add_parser("disable", help="Disable a DNS diversion rule")
    dns_rule_disable_parser.add_argument("id")
    _add_dns_common_paths(dns_rule_disable_parser, include_resolv_conf=False, include_snapshot=False)
    dns_rule_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_rule_disable_parser.set_defaults(handler=_dns_rule_set_enabled, enabled=False)

    dns_static_ip_parser = dns_subparsers.add_parser("static-ip", help="Manage static IP mappings")
    dns_static_ip_subparsers = dns_static_ip_parser.add_subparsers(dest="dns_static_ip_command")
    dns_static_ip_subparsers.required = True

    dns_static_ip_add_parser = dns_static_ip_subparsers.add_parser(
        "add", help="Add a static IP mapping"
    )
    dns_static_ip_add_parser.add_argument("domain")
    dns_static_ip_add_parser.add_argument("ip")
    dns_static_ip_add_parser.add_argument(
        "--disabled", action="store_true", help="Add the mapping disabled"
    )
    _add_dns_common_paths(dns_static_ip_add_parser, include_resolv_conf=False, include_snapshot=False)
    dns_static_ip_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_static_ip_add_parser.set_defaults(handler=_dns_static_ip_add)

    dns_static_ip_remove_parser = dns_static_ip_subparsers.add_parser(
        "remove", help="Remove static IP mapping(s) for a domain"
    )
    dns_static_ip_remove_parser.add_argument("domain")
    dns_static_ip_remove_parser.add_argument(
        "--ip", help="Only remove this specific IP; defaults to removing all IPs for the domain"
    )
    _add_dns_common_paths(dns_static_ip_remove_parser, include_resolv_conf=False, include_snapshot=False)
    dns_static_ip_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_static_ip_remove_parser.set_defaults(handler=_dns_static_ip_remove)

    config_parser = subparsers.add_parser("config", help="Manage WatchdogVPN configuration")
    config_subparsers = config_parser.add_subparsers(dest="config_command")
    config_subparsers.required = True

    config_set_parser = config_subparsers.add_parser("set", help="Set a configuration value")
    config_set_parser.add_argument("key", help="Configuration key, for example mode or rotation.test_url")
    config_set_parser.add_argument("value", help="Configuration value")
    config_set_parser.add_argument("--json", action="store_true", help="Print JSON")
    config_set_parser.set_defaults(handler=_config_set)

    config_routing_parser = config_subparsers.add_parser(
        "routing-contract",
        help="Show routing and capture coexistence contract",
    )
    config_routing_parser.add_argument("--json", action="store_true", help="Print JSON")
    config_routing_parser.set_defaults(handler=_config_routing_contract)

    config_lan_credentials_parser = config_subparsers.add_parser(
        "lan-sharing-credentials",
        help="Show LAN sharing credential status",
    )
    config_lan_credentials_parser.add_argument("--json", action="store_true", help="Print JSON")
    config_lan_credentials_parser.add_argument(
        "--show-secret",
        action="store_true",
        help="Print the LAN sharing password explicitly",
    )
    config_lan_credentials_parser.set_defaults(handler=_config_lan_sharing_credentials)

    stats_parser = subparsers.add_parser("stats", help="Inspect local observability metrics")
    stats_subparsers = stats_parser.add_subparsers(dest="stats_command")
    stats_subparsers.required = True

    stats_status_parser = stats_subparsers.add_parser("status", help="Show metrics status")
    stats_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_status_parser.set_defaults(handler=_stats_status)

    stats_summary_parser = stats_subparsers.add_parser("summary", help="Show aggregate metrics summary")
    stats_summary_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_summary_parser.set_defaults(handler=_stats_summary)

    stats_purge_parser = stats_subparsers.add_parser("purge", help="Purge local observability metrics")
    stats_purge_parser.add_argument("--yes", action="store_true", help="Confirm metrics purge")
    stats_purge_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_purge_parser.set_defaults(handler=_stats_purge)

    stats_privacy_parser = stats_subparsers.add_parser("privacy-mode", help="Set metrics privacy mode")
    stats_privacy_parser.add_argument(
        "mode",
        choices=[item.value for item in MetricsRedactionMode],
        help="Metrics privacy mode",
    )
    stats_privacy_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_privacy_parser.set_defaults(handler=_stats_privacy_mode)

    rules_parser = subparsers.add_parser("rules", help="Inspect configured routing rules")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command")
    rules_subparsers.required = True

    rules_list_parser = rules_subparsers.add_parser("list", help="List routing rule groups")
    rules_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_list_parser.set_defaults(handler=_rules_list)

    rules_explain_parser = rules_subparsers.add_parser(
        "explain",
        help="Explain how configured rules would handle hypothetical traffic",
    )
    rules_explain_parser.add_argument("--domain", help="Traffic domain name")
    rules_explain_parser.add_argument("--ip", help="Traffic destination IP")
    rules_explain_parser.add_argument("--port", type=int, help="Traffic destination port")
    rules_explain_parser.add_argument("--protocol", help="Traffic protocol, for example tls")
    rules_explain_parser.add_argument("--network", help="Network transport, for example tcp")
    rules_explain_parser.add_argument("--process-name", help="Process executable name")
    rules_explain_parser.add_argument("--process-path", help="Exact process executable path")
    rules_explain_parser.add_argument("--ruleset-trust-file", help="Rule-set trust registry JSON file")
    rules_explain_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_explain_parser.set_defaults(handler=_rules_explain)

    rules_enable_parser = rules_subparsers.add_parser("enable", help="Enable a rule group")
    rules_enable_parser.add_argument("group")
    rules_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_enable_parser.set_defaults(handler=_rules_set_group_enabled, enabled=True)

    rules_disable_parser = rules_subparsers.add_parser("disable", help="Disable a rule group")
    rules_disable_parser.add_argument("group")
    rules_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_disable_parser.set_defaults(handler=_rules_set_group_enabled, enabled=False)

    rules_add_rule_parser = rules_subparsers.add_parser("add-rule", help="Add a rule to a group")
    rules_add_rule_parser.add_argument("group")
    rules_add_rule_parser.add_argument("rule_id")
    rules_add_rule_parser.add_argument("--action", required=True, help="Rule action")
    rules_add_rule_parser.add_argument(
        "--condition",
        action="append",
        required=True,
        metavar="KEY=VALUE",
        help="Rule condition; repeat to add multiple values or condition types",
    )
    rules_add_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_add_rule_parser.set_defaults(handler=_rules_add_rule)

    rules_remove_rule_parser = rules_subparsers.add_parser(
        "remove-rule",
        help="Remove a rule from a group",
    )
    rules_remove_rule_parser.add_argument("group")
    rules_remove_rule_parser.add_argument("rule_id")
    rules_remove_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_remove_rule_parser.set_defaults(handler=_rules_remove_rule)

    rules_set_priority_parser = rules_subparsers.add_parser(
        "set-priority", help="Set a rule group's priority"
    )
    rules_set_priority_parser.add_argument("group")
    rules_set_priority_parser.add_argument("priority", type=int)
    rules_set_priority_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_set_priority_parser.set_defaults(handler=_rules_set_priority)

    rules_enable_rule_parser = rules_subparsers.add_parser(
        "enable-rule", help="Enable a single rule within a group"
    )
    rules_enable_rule_parser.add_argument("group")
    rules_enable_rule_parser.add_argument("rule_id")
    rules_enable_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_enable_rule_parser.set_defaults(handler=_rules_set_rule_enabled, enabled=True)

    rules_disable_rule_parser = rules_subparsers.add_parser(
        "disable-rule", help="Disable a single rule within a group"
    )
    rules_disable_rule_parser.add_argument("group")
    rules_disable_rule_parser.add_argument("rule_id")
    rules_disable_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_disable_rule_parser.set_defaults(handler=_rules_set_rule_enabled, enabled=False)

    rules_import_parser = rules_subparsers.add_parser("import", help="Import a rule group JSON file")
    rules_import_parser.add_argument("file")
    rules_import_parser.add_argument("--name", help="Override imported group name")
    rules_import_parser.add_argument(
        "--default-action",
        default="block",
        help="Route action for simple lists and external rules without explicit action",
    )
    rules_import_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Import supported rules while reporting unsupported entries",
    )
    rules_import_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the import without writing rule files",
    )
    rules_import_parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing group with the same name after writing a backup",
    )
    rules_import_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_import_parser.set_defaults(handler=_rules_import)

    rules_export_parser = rules_subparsers.add_parser("export", help="Export a rule group")
    rules_export_parser.add_argument("group")
    rules_export_parser.add_argument("--output", help="Write exported group JSON to this file")
    rules_export_parser.add_argument("--json", action="store_true", help="Print JSON")
    rules_export_parser.set_defaults(handler=_rules_export)

    ruleset_parser = subparsers.add_parser(
        "ruleset",
        help="Inspect and refresh trusted remote or built-in rule sets",
    )
    ruleset_subparsers = ruleset_parser.add_subparsers(dest="ruleset_command")
    ruleset_subparsers.required = True

    ruleset_status_parser = ruleset_subparsers.add_parser("status", help="Show rule-set trust and cache status")
    ruleset_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    ruleset_status_parser.set_defaults(handler=_ruleset_status)

    ruleset_refresh_parser = ruleset_subparsers.add_parser(
        "refresh",
        help="Refresh trusted rule-set cache files",
    )
    ruleset_refresh_parser.add_argument("ids", nargs="*", help="Rule-set IDs to refresh; defaults to all policies")
    ruleset_refresh_parser.add_argument(
        "--referenced-only",
        action="store_true",
        help="Refresh only rule sets referenced by enabled routing rules",
    )
    ruleset_refresh_parser.add_argument("--force", action="store_true", help="Refresh even when cache is not due")
    ruleset_refresh_parser.add_argument("--no-evict", action="store_true", help="Do not remove unowned cache files")
    ruleset_refresh_parser.add_argument("--json", action="store_true", help="Print JSON")
    ruleset_refresh_parser.set_defaults(handler=_ruleset_refresh)

    ruleset_add_parser = ruleset_subparsers.add_parser(
        "add", help="Define a rule-set trust policy"
    )
    ruleset_add_parser.add_argument("id")
    ruleset_add_parser.add_argument(
        "--kind", required=True, choices=[item.value for item in RuleSetKind]
    )
    ruleset_add_parser.add_argument("--source", required=True, help="Rule-set URL or built-in identifier")
    ruleset_add_parser.add_argument(
        "--sha256", help="Expected SHA-256 hex digest; required for --kind remote"
    )
    ruleset_add_parser.add_argument(
        "--critical", dest="critical", action="store_true", default=None,
        help="Treat load failure as fail-closed (default)",
    )
    ruleset_add_parser.add_argument(
        "--no-critical", dest="critical", action="store_false",
        help="Treat load failure as warn-and-skip",
    )
    ruleset_add_parser.add_argument(
        "--update-interval-seconds", type=int, help="Refresh interval; default 86400"
    )
    ruleset_add_parser.add_argument(
        "--max-stale-seconds", type=int, help="Maximum cache staleness; default 604800"
    )
    ruleset_add_parser.add_argument(
        "--failure-behavior",
        choices=[item.value for item in RuleSetFailureBehavior],
        help="Override the failure-behavior derived from --critical",
    )
    ruleset_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    ruleset_add_parser.set_defaults(handler=_ruleset_add)

    ruleset_remove_parser = ruleset_subparsers.add_parser(
        "remove", help="Remove a rule-set trust policy"
    )
    ruleset_remove_parser.add_argument("id")
    ruleset_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    ruleset_remove_parser.set_defaults(handler=_ruleset_remove)

    app_policy_parser = subparsers.add_parser(
        "app-policy",
        help="Manage minimal Linux app/process policy",
    )
    app_policy_subparsers = app_policy_parser.add_subparsers(dest="app_policy_command")
    app_policy_subparsers.required = True

    app_policy_status_parser = app_policy_subparsers.add_parser("status", help="Show app policy")
    app_policy_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_status_parser.set_defaults(handler=_app_policy_status)

    app_policy_enable_parser = app_policy_subparsers.add_parser("enable", help="Enable app policy")
    app_policy_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_enable_parser.set_defaults(handler=_app_policy_set_enabled, enabled=True)

    app_policy_disable_parser = app_policy_subparsers.add_parser("disable", help="Disable app policy")
    app_policy_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_disable_parser.set_defaults(handler=_app_policy_set_enabled, enabled=False)

    app_policy_mode_parser = app_policy_subparsers.add_parser("mode", help="Set app policy mode")
    app_policy_mode_parser.add_argument(
        "mode",
        choices=[item.value for item in AppPolicyMode],
        help="App policy mode",
    )
    app_policy_mode_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_mode_parser.set_defaults(handler=_app_policy_set_mode)

    app_policy_default_action_parser = app_policy_subparsers.add_parser(
        "default-action",
        help="Set app policy default action",
    )
    app_policy_default_action_parser.add_argument(
        "default_action",
        choices=[item.value for item in AppPolicyAction],
        help="Default route action",
    )
    app_policy_default_action_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_default_action_parser.set_defaults(handler=_app_policy_set_default_action)

    app_policy_add_parser = app_policy_subparsers.add_parser("add", help="Add an app policy rule")
    app_policy_add_match = app_policy_add_parser.add_mutually_exclusive_group(required=True)
    app_policy_add_match.add_argument("--process-name", help="Process executable name")
    app_policy_add_match.add_argument("--process-path", help="Exact process executable path")
    app_policy_add_match.add_argument(
        "--process-path-regex", help="Regex matching a process executable path"
    )
    app_policy_add_match.add_argument("--user", help="Unix username")
    app_policy_add_match.add_argument("--user-id", type=int, help="Unix numeric user ID")
    app_policy_add_parser.add_argument(
        "--action",
        required=True,
        help="Route action: current, direct, block, or group:<name>",
    )
    app_policy_add_parser.add_argument("--id", help="Rule ID; generated when omitted")
    app_policy_add_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_add_parser.set_defaults(handler=_app_policy_add)

    app_policy_remove_parser = app_policy_subparsers.add_parser("remove", help="Remove an app policy rule")
    app_policy_remove_parser.add_argument("rule_id")
    app_policy_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_remove_parser.set_defaults(handler=_app_policy_remove)

    app_policy_enable_rule_parser = app_policy_subparsers.add_parser(
        "enable-rule", help="Enable a single app policy rule"
    )
    app_policy_enable_rule_parser.add_argument("rule_id")
    app_policy_enable_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_enable_rule_parser.set_defaults(handler=_app_policy_set_rule_enabled, enabled=True)

    app_policy_disable_rule_parser = app_policy_subparsers.add_parser(
        "disable-rule", help="Disable a single app policy rule"
    )
    app_policy_disable_rule_parser.add_argument("rule_id")
    app_policy_disable_rule_parser.add_argument("--json", action="store_true", help="Print JSON")
    app_policy_disable_rule_parser.set_defaults(handler=_app_policy_set_rule_enabled, enabled=False)

    chain_parser = subparsers.add_parser("chain", help="Manage proxy route chains")
    chain_subparsers = chain_parser.add_subparsers(dest="chain_command")
    chain_subparsers.required = True

    chain_list_parser = chain_subparsers.add_parser("list", help="List route chains")
    chain_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_list_parser.set_defaults(handler=_chain_list)

    chain_show_parser = chain_subparsers.add_parser("show", help="Show a route chain")
    chain_show_parser.add_argument("id")
    chain_show_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_show_parser.set_defaults(handler=_chain_show)

    chain_create_parser = chain_subparsers.add_parser("create", help="Create a route chain")
    chain_create_parser.add_argument("id")
    chain_create_parser.add_argument(
        "--hop",
        action="append",
        required=True,
        metavar="TYPE:TARGET",
        help="Chain hop, e.g. profile:my-node or group:my-group; repeat for multiple hops",
    )
    chain_create_parser.add_argument("--description", help="Free-form chain description")
    chain_create_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_create_parser.set_defaults(handler=_chain_create)

    chain_add_hop_parser = chain_subparsers.add_parser("add-hop", help="Append a hop to a route chain")
    chain_add_hop_parser.add_argument("id")
    chain_add_hop_parser.add_argument("--type", required=True, choices=[item.value for item in ChainHopType])
    chain_add_hop_parser.add_argument("--target", required=True, help="Profile ID or node-group name")
    chain_add_hop_parser.add_argument(
        "--selection-policy",
        choices=["group_policy"],
        help="Only valid for --type group",
    )
    chain_add_hop_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_add_hop_parser.set_defaults(handler=_chain_add_hop)

    chain_remove_hop_parser = chain_subparsers.add_parser(
        "remove-hop", help="Remove a hop from a route chain by position"
    )
    chain_remove_hop_parser.add_argument("id")
    chain_remove_hop_parser.add_argument(
        "--index", type=int, required=True, help="1-based hop position, see `chain show`"
    )
    chain_remove_hop_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_remove_hop_parser.set_defaults(handler=_chain_remove_hop)

    chain_enable_parser = chain_subparsers.add_parser("enable", help="Enable a route chain")
    chain_enable_parser.add_argument("id")
    chain_enable_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_enable_parser.set_defaults(handler=_chain_set_enabled, enabled=True)

    chain_disable_parser = chain_subparsers.add_parser("disable", help="Disable a route chain")
    chain_disable_parser.add_argument("id")
    chain_disable_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_disable_parser.set_defaults(handler=_chain_set_enabled, enabled=False)

    chain_remove_parser = chain_subparsers.add_parser("remove", help="Remove a route chain")
    chain_remove_parser.add_argument("id")
    chain_remove_parser.add_argument("--json", action="store_true", help="Print JSON")
    chain_remove_parser.set_defaults(handler=_chain_remove)

    return parser


def _connection_connect(args: argparse.Namespace) -> int:
    try:
        response = WatchdogIPCClient().connect(args.profile_id)
    except WatchdogIPCError as exc:
        return _connection_ipc_error_output("connect", args, exc)
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Connected",
        command="connect",
    )


def _connection_disconnect(args: argparse.Namespace) -> int:
    try:
        response = WatchdogIPCClient().disconnect()
    except WatchdogIPCError as exc:
        return _connection_ipc_error_output("disconnect", args, exc)
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Disconnected",
        command="disconnect",
    )


def _connection_status(args: argparse.Namespace) -> int:
    try:
        response = WatchdogIPCClient().status()
    except WatchdogIPCError as exc:
        return _connection_ipc_error_output("status", args, exc)
    if args.json:
        _print_json(_connection_response_document(response, command="status"))
        return 0 if response.ok else 70
    if not response.ok:
        _error(response.error or "daemon command failed")
        for hint in _connection_recovery_hints(response.error or "daemon command failed"):
            print(f"hint: {hint}", file=sys.stderr)
        return 70
    _print_connection_state(
        response.payload.get("state", {}),
        command="status",
        no_color=bool(getattr(args, "no_color", False)),
    )
    return 0


def _connection_rotate(args: argparse.Namespace) -> int:
    try:
        response = WatchdogIPCClient().rotate(force=bool(args.force))
    except WatchdogIPCError as exc:
        return _connection_ipc_error_output("rotate", args, exc)
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Rotation requested",
        command="rotate",
    )


def _version(args: argparse.Namespace) -> int:
    version = _watchdogvpn_version(args.version_source)
    if args.json:
        _print_json(
            {
                "product": "WatchdogVPN",
                "version": version,
                "python_cli": True,
            }
        )
    else:
        print(f"WatchdogVPN {version}")
    return 0


def _watchdogvpn_version(source: str | None = None) -> str:
    path = Path(source).expanduser() if source else Path(__file__).resolve().parents[1] / "bin" / "watchdogvpn"
    text = path.read_text(encoding="utf-8")
    match = re.search(r'^VERSION="([^"]+)"$', text, flags=re.MULTILINE)
    if not match:
        raise ParseError(f"WatchdogVPN version marker not found in {path}")
    return match.group(1)


def _panic(args: argparse.Namespace) -> int:
    script = _panic_script_path(args.panic_script)
    completed = subprocess.run([str(script), args.mode], check=False)
    return int(completed.returncode)


def _panic_script_path(value: str | None) -> Path:
    if value:
        candidates = [Path(value).expanduser()]
    elif os.environ.get("WATCHDOGVPN_PANIC_SCRIPT"):
        candidates = [Path(os.environ["WATCHDOGVPN_PANIC_SCRIPT"]).expanduser()]
    else:
        candidates = [
            Path.cwd() / "bin" / "watchdog_panic",
            Path(__file__).resolve().parents[1] / "bin" / "watchdog_panic",
            Path("/usr/local/bin/watchdog_panic"),
        ]
    script = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
    if not script.exists():
        raise FileNotFoundError(
            "watchdog_panic not found; run from the WatchdogVPN checkout or set WATCHDOGVPN_PANIC_SCRIPT"
        )
    if not os.access(script, os.X_OK):
        raise PermissionError(f"panic script is not executable: {script}")
    return script


def _doctor(args: argparse.Namespace) -> int:
    script = _doctor_script_path(args.doctor_script)
    command = [str(script)]
    if args.json:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        _print_json(
            {
                "command": command,
                "doctor_exit_code": int(completed.returncode),
                "doctor_stdout": completed.stdout,
                "doctor_stderr": completed.stderr,
                "read_only": True,
                "mutates_runtime": False,
            }
        )
        return int(completed.returncode)
    env = os.environ.copy()
    if bool(getattr(args, "no_color", False)):
        env["NO_COLOR"] = "1"
    completed = subprocess.run(command, check=False, env=env)
    return int(completed.returncode)


def _doctor_script_path(value: str | None) -> Path:
    script = _support_script_path(
        "doctor.sh",
        value,
        "WATCHDOGVPN_DOCTOR_SCRIPT",
        "doctor.sh not found; install WatchdogVPN again, run from the checkout, or set WATCHDOGVPN_REPO_DIR",
    )
    if not os.access(script, os.X_OK):
        raise PermissionError(f"doctor script is not executable: {script}")
    return script


def _support_script_path(
    script_name: str,
    explicit_value: str | None,
    env_var: str,
    missing_message: str,
) -> Path:
    if explicit_value:
        candidates = [Path(explicit_value).expanduser()]
    elif os.environ.get(env_var):
        candidates = [Path(os.environ[env_var]).expanduser()]
    else:
        candidates = []
        if os.environ.get("WATCHDOGVPN_REPO_DIR"):
            candidates.append(Path(os.environ["WATCHDOGVPN_REPO_DIR"]).expanduser() / script_name)
        candidates.append(Path(__file__).resolve().parents[1] / script_name)
        if os.environ.get("WATCHDOGVPN_INSTALLED_LIB"):
            candidates.append(Path(os.environ["WATCHDOGVPN_INSTALLED_LIB"]).expanduser() / script_name)
        candidates.append(Path("/usr/local/lib/watchdogvpn") / script_name)
        candidates.append(Path.cwd() / script_name)
    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            deduped.append(candidate)
    script = next((candidate for candidate in deduped if candidate.exists()), deduped[0])
    if not script.exists():
        raise FileNotFoundError(missing_message)
    return script


def _setup(args: argparse.Namespace) -> int:
    plan = _setup_plan(args)
    if not args.dry_run and plan["has_changes"] and not args.yes:
        raise ParseError("setup requires --yes to write local state, or --dry-run to preview")
    if not args.acknowledge_backup_warning and not args.dry_run and plan["has_changes"]:
        raise ParseError("setup requires --acknowledge-backup-warning before writing local setup changes")

    backup_path = None
    if not args.dry_run and plan["has_changes"]:
        backup_path = _create_setup_backup(plan)
        _apply_setup(args, plan)
    if not plan["has_changes"]:
        outcome = "no_changes"
    elif args.dry_run:
        outcome = "dry_run"
    else:
        outcome = "applied"
    data = {
        **plan,
        "dry_run": bool(args.dry_run),
        "applied": bool(not args.dry_run and plan["has_changes"]),
        "outcome": outcome,
        "backup_path": str(backup_path) if backup_path else None,
        "backup_warning_acknowledged": bool(args.acknowledge_backup_warning),
    }
    if args.json:
        _print_json(data)
        return 0
    _print_setup_plan(data)
    return 0


def _setup_plan(args: argparse.Namespace) -> dict[str, object]:
    operations: list[dict[str, object]] = []
    if args.language or args.autostart or args.autoconnect:
        state = StateManager().load()
        if args.language:
            _append_setup_value_change(
                operations,
                target="selection-state",
                key="selected_language",
                current=state["selected_language"],
                requested=args.language,
            )
            _append_setup_value_change(
                operations,
                target="selection-state",
                key="language_mode",
                current=state["language_mode"],
                requested="manual",
            )
        if args.autostart:
            _append_setup_value_change(
                operations,
                target="selection-state",
                key="app_autostart_enabled",
                current=state["app_autostart_enabled"],
                requested=args.autostart == "enable",
            )
        if args.autoconnect:
            _append_setup_value_change(
                operations,
                target="selection-state",
                key="vpn_autoconnect_enabled",
                current=state["vpn_autoconnect_enabled"],
                requested=args.autoconnect == "enable",
            )
    if args.profile_uri:
        profile = parse_uri(args.profile_uri)
        fingerprint = profile_fingerprint(profile)
        duplicate = next(
            (
                existing
                for existing in ProfileStore().list()
                if existing.source == ProfileSource.MANUAL
                and profile_fingerprint(existing) == fingerprint
            ),
            None,
        )
        if duplicate is None:
            operations.append(
                {
                    "target": "profiles",
                    "action": "import-profile-uri",
                    "profile": _profile_summary(profile),
                }
            )
    if args.provider_url:
        provider = _setup_provider_document(args.provider_url, args.provider_name)
        existing_providers = ProviderStore().list()
        existing_by_id = next(
            (existing for existing in existing_providers if existing.id == provider.id),
            None,
        )
        if existing_by_id is not None and not _setup_provider_definition_matches(
            existing_by_id,
            provider,
        ):
            raise ParseError(
                f"provider id already exists with a different definition: {provider.id}; "
                "use `watchdog provider remove` before replacing it"
            )
        existing_by_url = next(
            (
                existing
                for existing in existing_providers
                if normalized_provider_url(existing.url) == provider.url
            ),
            None,
        )
        if existing_by_url is not None and existing_by_url.id != provider.id:
            raise ParseError(f"provider already exists: {existing_by_url.id}")
        if existing_by_id is None:
            if len(existing_providers) >= 2:
                raise ParseError("maximum 2 external providers allowed")
            operations.append(
                {
                    "target": "providers",
                    "action": "store-provider-url",
                    "provider": _provider_summary(provider),
                    "network_fetch_performed": False,
                }
            )
    if args.kill_switch:
        app_config = AppConfig().load()
        _append_setup_value_change(
            operations,
            target="settings",
            key="kill_switch.enabled",
            current=app_config["kill_switch"]["enabled"],
            requested=args.kill_switch == "enable",
        )
    if args.dns_mode:
        dns_policy = DNSPolicyStore().load()
        _append_setup_value_change(
            operations,
            target="dns-policy",
            key="mode",
            current=dns_policy.mode.value,
            requested=args.dns_mode,
        )
    if args.app_policy or args.app_policy_mode or args.app_policy_default_action:
        app_policy = AppPolicyStore().load()
        if args.app_policy:
            _append_setup_value_change(
                operations,
                target="app-policy",
                key="enabled",
                current=app_policy.enabled,
                requested=args.app_policy == "enable",
            )
        if args.app_policy_mode:
            _append_setup_value_change(
                operations,
                target="app-policy",
                key="mode",
                current=app_policy.mode.value,
                requested=args.app_policy_mode,
            )
        if args.app_policy_default_action:
            _append_setup_value_change(
                operations,
                target="app-policy",
                key="default_action",
                current=app_policy.default_action.value,
                requested=args.app_policy_default_action,
            )
    sections = sorted({str(item["target"]) for item in operations})
    return {
        "has_changes": bool(operations),
        "operations": operations,
        "sections": sections,
        "backup_warning": BACKUP_SENSITIVE_WARNING,
        "network_fetch_performed": False,
        "runtime_action_executed": False,
    }


def _append_setup_value_change(
    operations: list[dict[str, object]],
    *,
    target: str,
    key: str,
    current: object,
    requested: object,
) -> None:
    if current == requested:
        return
    operations.append({"target": target, "key": key, "value": requested})


def _apply_setup(args: argparse.Namespace, plan: dict[str, object]) -> None:
    sections = set(plan.get("sections", []))
    if "selection-state" in sections:
        state_manager = StateManager()
        state = state_manager.load()
        if args.language:
            state["selected_language"] = args.language
            state["language_mode"] = "manual"
        if args.autostart:
            state["app_autostart_enabled"] = args.autostart == "enable"
        if args.autoconnect:
            state["vpn_autoconnect_enabled"] = args.autoconnect == "enable"
        state_manager.save(state)
    if "settings" in sections:
        app_config_store = AppConfig()
        app_config = app_config_store.load()
        app_config["kill_switch"]["enabled"] = args.kill_switch == "enable"
        app_config_store.save(app_config)
    if "dns-policy" in sections:
        dns_store = DNSPolicyStore()
        dns_policy = dns_store.load()
        dns_policy.mode = DNSMode(args.dns_mode)
        dns_store.save(DNSPolicy.from_dict(dns_policy.to_dict()))
    if "app-policy" in sections:
        app_policy_store = AppPolicyStore()
        app_policy = app_policy_store.load()
        if args.app_policy:
            app_policy.enabled = args.app_policy == "enable"
        if args.app_policy_mode:
            app_policy.mode = AppPolicyMode(args.app_policy_mode)
        if args.app_policy_default_action:
            app_policy.default_action = AppPolicyAction(args.app_policy_default_action)
        app_policy_store.save(AppPolicy.from_dict(app_policy.to_dict()))
    if "profiles" in sections:
        ManualProvider(rotation_prompt=lambda _profile: False).from_uri(args.profile_uri)
    if "providers" in sections:
        ProviderStore().add(_setup_provider_document(args.provider_url, args.provider_name))


def _create_setup_backup(plan: dict[str, object]) -> Path:
    sections = [str(section) for section in plan.get("sections", [])]
    return BackupManager().create_backup(
        reason="pre-setup",
        sections=sections,
    ).path


def _setup_provider_document(url: str, name: str | None) -> Provider:
    normalized_url = validate_subscription_url(url)
    label = name or _setup_provider_id(normalized_url)
    return Provider(
        id=_setup_provider_id(label),
        name=label,
        url=normalized_url,
        last_updated=None,
        profiles=[],
        rotation_enabled=False,
        metadata={"setup_staged_without_fetch": True},
    )


def _setup_provider_definition_matches(existing: Provider, requested: Provider) -> bool:
    return (
        existing.id == requested.id
        and existing.name == requested.name
        and normalized_provider_url(existing.url) == normalized_provider_url(requested.url)
    )


def _setup_provider_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", value.strip().lower())
    slug = slug.strip("-_")
    return slug[:64] or "provider"


def _print_setup_plan(data: dict[str, object]) -> None:
    print("WatchdogVPN setup plan")
    print(f"Dry run: {_on_off(bool(data['dry_run']))}")
    print(f"Applied: {_on_off(bool(data['applied']))}")
    print(f"Outcome: {data['outcome']}")
    print(f"Runtime action executed: {_on_off(bool(data['runtime_action_executed']))}")
    print(f"Network fetch performed: {_on_off(bool(data['network_fetch_performed']))}")
    print(f"Backup: {data.get('backup_path') or '-'}")
    operations = data.get("operations", [])
    if not operations:
        print("Operations: none")
        print("Requested setup configuration is already effective or no changes were requested.")
        return
    print("Operations:")
    if isinstance(operations, list):
        for item in operations:
            if isinstance(item, dict):
                label = item.get("key") or item.get("action") or item.get("target")
                print(f"  {item.get('target')}: {label}")


def _uninstall(args: argparse.Namespace) -> int:
    mode = _uninstall_mode(args)
    if not args.dry_run and not args.yes:
        raise ParseError("uninstall requires --yes unless --dry-run is used")
    if mode == "delete-all-data" and args.confirm_delete != "DELETE" and not args.dry_run:
        raise ParseError("uninstall --delete-all-data requires --confirm-delete DELETE")
    if mode in {"backup-first", "delete-all-data"} and args.encrypt_backup and not args.backup_password_env:
        raise ParseError("--encrypt-backup requires --backup-password-env")

    backup_path: Path | None = None
    if mode in {"backup-first", "delete-all-data"}:
        backup_path = _uninstall_backup_output(args.backup_output)
        _validate_uninstall_backup_output(backup_path)

    if not args.dry_run and mode in {"backup-first", "delete-all-data"}:
        password = _uninstall_backup_password(args)
        reason = "pre-uninstall-delete" if mode == "delete-all-data" else "uninstall-export"
        BackupManager().create_backup(
            backup_path,
            reason=reason,
            encrypt=bool(args.encrypt_backup),
            password=password,
        )

    command = _uninstall_script_command(args, mode)
    data = {
        "mode": mode,
        "dry_run": bool(args.dry_run),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "encrypted_backup": bool(args.encrypt_backup),
        "command": command,
        "contract": _uninstall_contract(mode),
    }
    if args.dry_run:
        data["uninstall_exit_code"] = None
        data["uninstall_stdout"] = ""
        data["uninstall_stderr"] = ""
        if args.json:
            _print_json(data)
            return 0
        _print_uninstall_plan(data)
        return 0
    if args.json:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        data["uninstall_exit_code"] = int(completed.returncode)
        data["uninstall_stdout"] = completed.stdout
        data["uninstall_stderr"] = completed.stderr
        _print_json(data)
        return int(completed.returncode)
    _print_uninstall_plan(data)
    completed = subprocess.run(command, check=False)
    return int(completed.returncode)


def _uninstall_mode(args: argparse.Namespace) -> str:
    if args.keep_data:
        return "keep-data"
    if args.backup_first:
        return "backup-first"
    if args.delete_all_data:
        return "delete-all-data"
    if not sys.stdin.isatty():
        raise ParseError(
            "uninstall requires one of: --keep-data, --backup-first, --delete-all-data"
        )
    print("WatchdogVPN uninstall options:")
    print("1. Keep local data")
    print("2. Export backup first, then uninstall")
    print("3. Delete all WatchdogVPN data")
    answer = input("Choose 1, 2 or 3: ").strip()
    if answer == "1":
        return "keep-data"
    if answer == "2":
        return "backup-first"
    if answer == "3":
        return "delete-all-data"
    raise ParseError("uninstall choice must be 1, 2 or 3")


def _uninstall_backup_output(value: str | None) -> Path:
    if value:
        return Path(value).expanduser()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path.home() / f"watchdogvpn-uninstall-backup-{stamp}.zip"


def _validate_uninstall_backup_output(path: Path) -> None:
    resolved = path.resolve(strict=False)
    managed_roots = [
        resolve_config_dir(),
        Path("/etc/watchdogvpn"),
        Path("/var/lib/watchdogvpn"),
        Path("/var/log/myvpn"),
    ]
    for root in managed_roots:
        root_resolved = root.resolve(strict=False)
        if resolved == root_resolved or root_resolved in resolved.parents:
            raise ParseError(
                f"uninstall backup output must be outside WatchdogVPN-owned paths: {path}"
            )


def _uninstall_backup_password(args: argparse.Namespace) -> str | None:
    if not args.encrypt_backup:
        return None
    password = os.environ.get(args.backup_password_env or "")
    if not password:
        raise ParseError("encrypted uninstall backup password environment variable is empty")
    return password


def _uninstall_script_command(args: argparse.Namespace, mode: str) -> list[str]:
    script = _uninstall_script_path(args.uninstall_script)
    command = [str(script)]
    if args.dry_run:
        command.append("--dry-run")
    if args.yes:
        command.append("--yes")
    if args.skip_dns_rescue:
        command.append("--skip-dns-rescue")
    if mode == "delete-all-data":
        command.extend(
            [
                "--purge-config",
                "--purge-logs",
                "--purge-state",
                "--confirm-delete",
                "DELETE",
            ]
        )
    return command


def _uninstall_script_path(value: str | None) -> Path:
    script = _support_script_path(
        "uninstall.sh",
        value,
        "WATCHDOGVPN_UNINSTALL_SCRIPT",
        "uninstall.sh not found; install WatchdogVPN again, run from the checkout, or set WATCHDOGVPN_REPO_DIR",
    )
    if not os.access(script, os.X_OK):
        raise PermissionError(f"uninstall script is not executable: {script}")
    return script


def _print_uninstall_plan(data: dict[str, object]) -> None:
    print("WatchdogVPN uninstall plan")
    print(f"Mode: {data['mode']}")
    print(f"Dry run: {_on_off(bool(data['dry_run']))}")
    print(f"Backup: {data['backup_path'] or '-'}")
    print(f"Encrypted backup: {_on_off(bool(data['encrypted_backup']))}")
    contract = data.get("contract", {})
    if isinstance(contract, dict):
        print("Product-managed files: " + ", ".join(contract.get("product_managed_files", [])))
        print("Preserved user state: " + ", ".join(contract.get("preserved_user_state", [])))
        print("Logs: " + str(contract.get("logs", "-")))
        print("Systemd units: " + ", ".join(contract.get("systemd_units", [])))
    print("Command:")
    print("  " + " ".join(str(part) for part in data["command"]))


def _uninstall_contract(mode: str) -> dict[str, object]:
    preserved = ["/etc/watchdogvpn", "/var/lib/watchdogvpn", "/var/log/myvpn"]
    if mode == "delete-all-data":
        preserved = []
    return {
        "product_managed_files": [
            "/usr/local/bin/watchdog",
            "/usr/local/bin/watchdogvpn-daemon",
            "/usr/local/bin/watchdog_panic",
            "WatchdogVPN systemd units",
        ],
        "preserved_user_state": preserved,
        "logs": "preserved" if mode != "delete-all-data" else "removed after pre-delete backup",
        "backups": "never removed by the CLI; pre-delete backup must be outside WatchdogVPN-owned paths",
        "systemd_units": [
            "watchdogvpn.service",
            "watchdogvpn-scheduled-rotation.service",
            "watchdogvpn-scheduled-rotation.timer",
            "vpn-domain-bypass.service",
            "vpn-domain-bypass.timer",
        ],
        "requires_explicit_consent": True,
    }


def _add_backup_create_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", help="Backup output path; defaults to config backups directory")
    parser.add_argument(
        "--section",
        action="append",
        choices=SUPPORTED_SECTION_NAMES,
        help="Backup section to include; repeat for multiple sections",
    )
    parser.add_argument("--encrypt", action="store_true", help="Encrypt backup using --password-env")
    parser.add_argument("--password-env", help="Environment variable containing the encrypted-backup password")
    parser.add_argument("--json", action="store_true", help="Print JSON")


def _add_backup_restore_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file")
    parser.add_argument(
        "--section",
        action="append",
        choices=SUPPORTED_SECTION_NAMES,
        help="Restore section; repeat for multiple sections",
    )
    parser.add_argument("--mode", choices=["replace", "merge"], default="replace", help="Restore mode")
    parser.add_argument("--confirm", help=f"Required literal {RESTORE_REPLACE_CONFIRMATION} for replace restore")
    parser.add_argument("--password-env", help="Environment variable containing the encrypted-backup password")
    parser.add_argument("--dry-run", action="store_true", help="Validate restore without writing local state")
    parser.add_argument("--json", action="store_true", help="Print JSON")


def _backup_create(args: argparse.Namespace) -> int:
    if args.encrypt and not args.password_env:
        raise ParseError("encrypted backup requires --password-env")
    output_path = Path(args.output).expanduser() if args.output else None
    password = _backup_password(args.password_env) if args.encrypt else None
    result = BackupManager().create_backup(
        output_path,
        sections=args.section,
        encrypt=bool(args.encrypt),
        password=password,
    )
    data = _backup_manifest_summary(result.path, result.manifest, encrypted=bool(args.encrypt))
    if args.json:
        _print_json(data)
    else:
        print(f"Backup created: {result.path}")
        print(f"Sections: {', '.join(data['sections'])}")
        print(f"Encrypted: {_on_off(bool(data['encrypted']))}")
        print(f"Sensitive: {_on_off(bool(data['sensitive']))}")
        print(str(data["sensitive_warning"]))
    return 0


def _backup_inspect(args: argparse.Namespace) -> int:
    password = _backup_password(args.password_env) if args.password_env else None
    parsed = BackupManager().inspect_backup(Path(args.file).expanduser(), password=password)
    data = _backup_manifest_summary(
        Path(args.file).expanduser(),
        parsed.manifest,
        encrypted=bool(parsed.encrypted),
    )
    data["valid"] = True
    if args.json:
        _print_json(data)
    else:
        print(f"Backup: {data['path']}")
        print(f"Valid: {_on_off(True)}")
        print(f"Sections: {', '.join(data['sections'])}")
        print(f"Encrypted: {_on_off(bool(data['encrypted']))}")
        print(str(data["sensitive_warning"]))
    return 0


def _backup_restore(args: argparse.Namespace) -> int:
    backup_path = Path(args.file).expanduser()
    password = _backup_password(args.password_env) if args.password_env else None
    manager = BackupManager()
    parsed = manager.inspect_backup(backup_path, password=password)
    selected_sections = args.section or list(parsed.manifest["sections"])
    missing = sorted(set(selected_sections) - set(parsed.manifest["sections"]))
    if missing:
        raise ParseError(f"backup does not contain requested sections: {', '.join(missing)}")
    if args.dry_run:
        if args.mode == "merge":
            unsupported = sorted(set(selected_sections) - set(MERGE_SECTION_NAMES))
            if unsupported:
                raise ParseError(f"merge restore does not support sections: {', '.join(unsupported)}")
        data = {
            **_backup_manifest_summary(backup_path, parsed.manifest, encrypted=bool(parsed.encrypted)),
            "dry_run": True,
            "restore_mode": args.mode,
            "selected_sections": selected_sections,
            "pre_restore_backup": None,
            "restore_would_write": False,
        }
        if args.json:
            _print_json(data)
        else:
            print(f"Restore dry run: {backup_path}")
            print(f"Mode: {args.mode}")
            print(f"Sections: {', '.join(selected_sections)}")
            print("Restore would write: no")
        return 0
    result = manager.restore_backup(
        backup_path,
        sections=selected_sections,
        mode=args.mode,
        replace_confirmation=args.confirm,
        password=password,
    )
    informational_sections = [
        section for section in selected_sections if section in INFORMATIONAL_SECTION_NAMES
    ]
    restored_sections = [
        section for section in selected_sections if section not in INFORMATIONAL_SECTION_NAMES
    ]
    data = {
        **_backup_manifest_summary(result.path, result.manifest, encrypted=bool(parsed.encrypted)),
        "dry_run": False,
        "restore_mode": args.mode,
        "selected_sections": selected_sections,
        "restored_sections": restored_sections,
        "informational_sections": informational_sections,
        "pre_restore_backup": str(result.pre_restore_backup),
        "restore_would_write": True,
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Backup restored: {result.path}")
        print(f"Mode: {args.mode}")
        print(f"Sections restored: {', '.join(restored_sections) or '-'}")
        if informational_sections:
            print(
                "Sections informational (not restored, no persisted state to write): "
                f"{', '.join(informational_sections)}"
            )
        print(f"Pre-restore backup: {result.pre_restore_backup}")
    return 0


def _backup_password(env_name: str | None) -> str:
    if not env_name:
        raise ParseError("backup password environment variable is required")
    password = os.environ.get(env_name)
    if not password:
        raise ParseError("backup password environment variable is empty")
    return password


def _backup_manifest_summary(path: Path, manifest: dict[str, object], *, encrypted: bool) -> dict[str, object]:
    return {
        "path": str(path),
        "schema_version": manifest.get("schema_version"),
        "format": manifest.get("format"),
        "created_at": manifest.get("created_at"),
        "reason": manifest.get("reason"),
        "sections": list(manifest.get("sections", [])),
        "encrypted": encrypted,
        "sensitive": bool(manifest.get("sensitive", True)),
        "sensitive_warning": manifest.get("sensitive_warning", BACKUP_SENSITIVE_WARNING),
        "normal_backup": True,
        "support_export": False,
        "redacted_export": False,
    }


def _connection_response_output(
    response: Response,
    json_output: bool,
    success_label: str,
    *,
    command: str,
) -> int:
    if json_output:
        _print_json(_connection_response_document(response, command=command))
        return 0 if response.ok else 70
    if not response.ok:
        _error(response.error or "daemon command failed")
        for hint in _connection_recovery_hints(response.error or "daemon command failed"):
            print(f"hint: {hint}", file=sys.stderr)
        return 70
    if "performed" in response.payload and not response.payload["performed"]:
        print("Rotation skipped: automatic actions are disabled (VPN is off).")
    else:
        print(success_label)
    if "profile_id" in response.payload:
        print(f"Profile: {response.payload['profile_id']}")
    if "state" in response.payload:
        _print_connection_state(response.payload["state"], command=command)
    return 0


def _connection_ipc_error_output(command: str, args: argparse.Namespace, exc: WatchdogIPCError) -> int:
    if bool(getattr(args, "json", False)):
        _print_json(_connection_error_document(command, str(exc), exit_code=exc.exit_code))
    else:
        _error(str(exc))
        for hint in _connection_recovery_hints(str(exc)):
            print(f"hint: {hint}", file=sys.stderr)
    return exc.exit_code


def _connection_response_document(response: Response, *, command: str) -> dict[str, object]:
    data = response.to_dict()
    payload = dict(data.get("payload") or {})
    state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
    error_kind = payload.get("error_kind")
    payload["lifecycle"] = _connection_lifecycle_summary(
        command=command,
        daemon_reachable=True,
        state=state if isinstance(state, dict) else {},
        error=response.error,
        error_kind=error_kind if isinstance(error_kind, str) else None,
    )
    if response.error:
        payload["recovery_hints"] = _connection_recovery_hints(response.error)
    data["payload"] = payload
    return data


def _connection_error_document(command: str, error: str, *, exit_code: int) -> dict[str, object]:
    return {
        "version": 1,
        "type": "response",
        "ok": False,
        "payload": {
            "lifecycle": _connection_lifecycle_summary(
                command=command,
                daemon_reachable=False,
                state={},
                error=error,
                error_kind=None,
            ),
            "recovery_hints": _connection_recovery_hints(error),
            "exit_code": exit_code,
        },
        "error": error,
    }


def _connection_lifecycle_summary(
    *,
    command: str,
    daemon_reachable: bool,
    state: dict[str, object],
    error: str | None,
    error_kind: str | None = None,
) -> dict[str, object]:
    desired_state = _connection_desired_state()
    runtime_status = str(state.get("status") or "unknown")
    proxy_active = bool(state.get("proxy_active", False))
    tun_active = bool(state.get("tun_active", False))
    lan_gateway_status = str(state.get("lan_gateway_status") or "disabled")
    runtime_active = proxy_active or tun_active or bool(state.get("lan_gateway_active", False))
    disconnected_cleanly = (
        daemon_reachable
        and desired_state == "off"
        and runtime_status in {"standby", "disconnected", "unknown"}
        and not runtime_active
        and lan_gateway_status in {"disabled", "configured", ""}
    )
    last_failure_reason = str(state.get("last_failure_reason") or "")
    failure_or_degraded = (
        bool(error)
        or runtime_status in FAILURE_STATUSES
        or lan_gateway_status == "degraded"
        or bool(last_failure_reason)
    )
    # profile_available is derived from a structured error_kind (set by
    # daemon/runtime_worker.py::_handle_connect), not by guessing at the
    # free-text error message (WDCLI-005: that used to substring-match
    # "profile not found", which silently defaulted to True for any other
    # failure wording, including "profile_id must be a non-empty string").
    # None means genuinely indeterminate: "invalid_input" has no profile
    # identity to assess at all, and an unstructured/transport-level error
    # (e.g. WatchdogIPCError, daemon never reached) carries no error_kind -
    # neither case should guess True or False.
    if error is None:
        profile_available: bool | None = True
    elif error_kind == "profile_not_found":
        profile_available = False
    elif error_kind == "connect_failed":
        profile_available = True
    else:
        profile_available = None
    profile_id = state.get("active_profile_id") or ""
    return {
        "command": command,
        "daemon_reachable": daemon_reachable,
        "desired_state": desired_state,
        "actual_runtime_state": runtime_status,
        "active_profile_id": profile_id,
        "runtime_active": runtime_active,
        "proxy_active": proxy_active,
        "tun_active": tun_active,
        "kill_switch_active": bool(state.get("kill_switch_active", False)),
        "lan_gateway_status": lan_gateway_status,
        "profile_available": profile_available,
        # Nothing in the codebase currently distinguishes "daemon reachable
        # but runtime subsystem down" from "daemon reachable" - the old
        # substring match on "unavailable" was guessing at a distinction
        # that doesn't exist anywhere else.
        "runtime_available": daemon_reachable,
        "disconnected_cleanly": disconnected_cleanly,
        "failure_or_degraded": failure_or_degraded,
        "last_failure_reason": last_failure_reason,
        "last_failure_at": str(state.get("last_failure_at") or ""),
        "cleanup_expectations": _connection_cleanup_expectations(command, state),
    }


def _connection_desired_state() -> str:
    try:
        state = StateManager().load()
    except PersistentStoreError:
        return "unknown"
    desired = state.get("vpn_desired_state", "off")
    return str(desired or "off")


def _connection_cleanup_expectations(command: str, state: dict[str, object]) -> dict[str, object]:
    if command != "disconnect":
        return {
            "applies": False,
            "reason": "cleanup proof applies to disconnect and lower runtime layers",
        }
    return {
        "applies": True,
        "process_cleanup": "daemon runtime driver disconnect is responsible for child process cleanup",
        "interface_cleanup": "driver cleanup applies where TUN or gateway mode created interfaces/routes",
        "dns_restore": "runtime disconnect restores saved DNS snapshot when present",
        "orphan_listener_cleanup": "driver disconnect removes owned local proxy listeners where applicable",
        "post_state": {
            "proxy_active": bool(state.get("proxy_active", False)),
            "tun_active": bool(state.get("tun_active", False)),
            "lan_gateway_status": str(state.get("lan_gateway_status") or "disabled"),
        },
    }


def _connection_recovery_hints(error: str) -> list[str]:
    lowered = error.lower()
    if "daemon is not running" in lowered:
        return [
            "start the daemon with: sudo systemctl start watchdogvpn",
            "for development, run: python3 -m daemon.main --standalone",
        ]
    if "stale" in lowered:
        return ["restart the daemon with: sudo systemctl restart watchdogvpn"]
    if "permission denied" in lowered:
        return ["add your user to the watchdogvpn group, then log out and back in"]
    if "did not respond" in lowered or "timed out" in lowered:
        return ["check daemon logs with: sudo journalctl -u watchdogvpn"]
    if "profile not found" in lowered:
        return ["run: watchdog profile list"]
    if "connect failed" in lowered:
        return [
            "run: watchdog status",
            "run diagnostics for the selected profile and check daemon logs",
        ]
    if "disconnect failed" in lowered:
        return [
            "run: watchdog status",
            "check daemon logs and run DNS/reset cleanup if DNS state remains changed",
        ]
    return []


def _print_connection_state(state: dict, *, command: str, no_color: bool = False) -> None:
    lifecycle = _connection_lifecycle_summary(
        command=command,
        daemon_reachable=True,
        state=state,
        error=None,
    )
    print(f"Daemon: {_semantic('reachable' if lifecycle['daemon_reachable'] else 'unreachable', no_color=no_color)}")
    print(f"Desired state: {_semantic(lifecycle['desired_state'], no_color=no_color)}")
    print(f"Status: {_semantic(state.get('status', 'unknown'), no_color=no_color)}")
    print(f"Actual runtime state: {_semantic(lifecycle['actual_runtime_state'], no_color=no_color)}")
    print(f"Mode: {state.get('mode', '-')}")
    active_profile_id = state.get("active_profile_id") or "-"
    print(f"Active profile: {active_profile_id}")
    print(f"TUN: {_on_off(bool(state.get('tun_active', False)), no_color=no_color)}")
    print(f"Proxy: {_on_off(bool(state.get('proxy_active', False)), no_color=no_color)}")
    lan_gateway_status = str(state.get("lan_gateway_status", "disabled"))
    print(f"LAN gateway: {_semantic(lan_gateway_status, no_color=no_color)}")
    if lan_gateway_status != "disabled" or state.get("lan_gateway_active"):
        print(f"LAN gateway interface: {state.get('lan_gateway_interface') or '-'}")
        print(f"LAN gateway clients: {state.get('lan_gateway_client_cidr') or '-'}")
        print(f"LAN gateway DNS: {state.get('lan_gateway_dns_mode') or '-'}")
    print(f"Kill switch: {_danger_on_off(bool(state.get('kill_switch_active', False)), no_color=no_color)}")
    print(f"Disconnected cleanly: {_on_off(bool(lifecycle['disconnected_cleanly']), no_color=no_color)}")
    print(f"Failure/degraded: {_danger_on_off(bool(lifecycle['failure_or_degraded']), no_color=no_color)}")
    last_failure_reason = str(lifecycle.get("last_failure_reason") or "")
    if last_failure_reason:
        last_failure_at = str(lifecycle.get("last_failure_at") or "-")
        print(f"Last failure: {_semantic(last_failure_reason, no_color=no_color)} at {last_failure_at}")
    if command == "disconnect":
        print("Cleanup expectations:")
        cleanup = lifecycle["cleanup_expectations"]
        if isinstance(cleanup, dict):
            for key in ("process_cleanup", "interface_cleanup", "dns_restore", "orphan_listener_cleanup"):
                print(f"  {key}: {cleanup.get(key)}")


def _profile_add(args: argparse.Namespace) -> int:
    rotation_prompt = (lambda _profile: False) if args.json else _prompt_rotation_pool
    provider = ManualProvider(rotation_prompt=rotation_prompt)
    if args.clipboard:
        profile = provider.from_clipboard()
        if profile is None:
            _error("clipboard does not contain supported profile content")
            return 66
    elif args.uri is not None:
        profile = provider.from_uri(args.uri)
    elif args.file:
        profile = provider.from_file(args.file)
    elif args.text:
        profile = provider.from_text(_read_text_input())
    else:
        raise AssertionError("unreachable profile add source")

    imported = provider.last_imported or [profile]
    data = {
        "imported_count": len(imported),
        "profiles": [_profile_summary(item) for item in imported],
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Imported {len(imported)} profile(s).")
    for item in imported:
        summary = _profile_summary(item)
        print(
            f"{item.id}\t{item.protocol.value}\t{summary['resilience_category']}\t"
            f"{item.name}\trotation={_on_off(item.in_rotation_pool)}"
        )
    return 0


def _profile_list(args: argparse.Namespace) -> int:
    store = ProfileStore()
    if args.pool:
        profiles = pool_builder.build_pool(store, ProviderStore(), AppConfig().load())
    else:
        profiles = store.list()
    data = [_profile_summary(profile) for profile in profiles]
    if args.json:
        _print_json(data)
        return 0
    if not profiles:
        print("No profiles found.")
        return 0
    _print_profile_list(
        profiles,
        wide=bool(args.wide),
        pool_only=bool(args.pool),
        no_color=bool(getattr(args, "no_color", False)),
    )
    return 0


def _profile_remove(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    store.remove(profile.id)
    data = {
        "removed": _profile_summary(profile),
        "rollback_point": {
            "kind": "profile-document",
            "profile": _profile_summary(profile),
            "raw_profile_config_included": False,
        },
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Removed profile: {profile.id}")
    print("Rollback: re-import the profile from the original local URI/file/provider source.")
    return 0


def _profile_set_enabled(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.enabled = bool(args.enabled)
    store.update(profile)
    data = {"profile": _profile_summary(profile)}
    if args.json:
        _print_json(data)
        return 0
    state = "enabled" if profile.enabled else "disabled"
    print(f"Profile {state}: {profile.id}")
    return 0


def _profile_rotation(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.in_rotation_pool = bool(args.enable or args.on)
    store.update(profile)
    data = {"profile": _profile_summary(profile)}
    if args.json:
        _print_json(data)
        return 0
    state = "enabled" if profile.in_rotation_pool else "disabled"
    print(f"Profile rotation {state}: {profile.id}")
    return 0


def _provider_add(args: argparse.Namespace) -> int:
    url = args.url or _prompt_required("Provider URL")
    name = args.name if args.name is not None else _prompt_optional("Provider name")
    provider = SubscriptionProvider().add(url, name)
    data = {"provider": _provider_summary(provider)}
    if args.json:
        _print_json(data)
        return 0
    print(f"Added provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"Profiles: {len(provider.profiles)}")
    return 0


def _provider_list(args: argparse.Namespace) -> int:
    providers = ProviderStore().list()
    summaries = [_provider_summary(provider) for provider in providers]
    if args.json:
        print(json.dumps(summaries, indent=2, sort_keys=True))
        return 0
    if not summaries:
        print("No providers found.")
        return 0
    rows = [
        (
            summary["id"],
            summary["name"],
            _on_off_plain(bool(summary["rotation_enabled"])),
            str(summary["node_count"]),
            str(summary["last_updated"] or "-"),
            str(summary["traffic"] or "-"),
            str(summary["expires_at"] or "-"),
        )
        for summary in summaries
    ]
    columns = ("ID", "Name", "Enabled", "Nodes", "Last update", "Traffic", "Expires")
    widths = [max(len(str(row[index])) for row in [columns, *rows]) for index in range(len(columns))]
    print(_format_profile_row(columns, widths))
    print(_format_profile_row(tuple("-" * width for width in widths), widths))
    for row in rows:
        print(
            _format_profile_row(
                row,
                widths,
                semantic_columns={2},
                no_color=bool(getattr(args, "no_color", False)),
            )
        )
    return 0


def _provider_stats(args: argparse.Namespace) -> int:
    provider = _require_provider(ProviderStore(), args.provider_id)
    summary = _provider_summary(provider)
    profiles = [
        profile
        for profile in ProfileStore().list()
        if profile.provider_id == provider.id
    ]
    protocols: dict[str, int] = {}
    enabled_nodes = 0
    rotation_nodes = 0
    for profile in profiles:
        protocols[profile.protocol.value] = protocols.get(profile.protocol.value, 0) + 1
        enabled_nodes += 1 if profile.enabled else 0
        rotation_nodes += 1 if profile.in_rotation_pool else 0
    data = {
        **summary,
        "enabled_nodes": enabled_nodes,
        "rotation_nodes": rotation_nodes,
        "protocols": protocols,
    }
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    print(f"Provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"URL: {_redact_url(provider.url)}")
    print(f"Rotation: {_on_off(provider.rotation_enabled)}")
    print(f"Nodes: {len(profiles)}")
    print(f"Enabled nodes: {enabled_nodes}")
    print(f"Rotation nodes: {rotation_nodes}")
    print(f"Last update: {provider.last_updated.isoformat() if provider.last_updated else '-'}")
    print(f"Traffic: {summary['traffic'] or '-'}")
    print(f"Expires: {summary['expires_at'] or '-'}")
    print(f"Protocols: {', '.join(f'{key}={value}' for key, value in sorted(protocols.items())) or '-'}")
    return 0


def _provider_update(args: argparse.Namespace) -> int:
    provider = SubscriptionProvider()
    if args.all:
        results = provider.update_all()
        if args.json:
            _print_json({"updated": results})
            return 0
        for provider_id, result in results.items():
            print(f"{provider_id}\t{result}")
        return 0
    changes = provider.update(args.provider_id)
    if args.json:
        _print_json({"provider_id": args.provider_id, "changes": changes})
        return 0
    print(f"Provider updated: {args.provider_id} changes={changes}")
    return 0


def _provider_remove(args: argparse.Namespace) -> int:
    provider = _require_provider(ProviderStore(), args.provider_id)
    SubscriptionProvider().remove(args.provider_id)
    data = {
        "removed": _provider_summary(provider),
        "rollback_point": {
            "kind": "provider-redacted-summary",
            "provider": _provider_summary(provider),
            "subscription_url_included": False,
        },
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Removed provider: {args.provider_id}")
    print("Rollback: add the provider again from the original subscription URL.")
    return 0


def _provider_edit(args: argparse.Namespace) -> int:
    if args.name is None and args.url is None:
        raise ParseError("provider edit requires --name or --url")
    provider_store = ProviderStore()
    provider = _require_provider(provider_store, args.provider_id)
    if args.name is not None:
        provider.name = args.name
    if args.url is not None:
        provider.url = args.url
    provider_store.update(provider)
    data = {"provider": _provider_summary(provider)}
    if args.json:
        _print_json(data)
        return 0
    print(f"Updated provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"URL: {_redact_url(provider.url)}")
    return 0


def _provider_rotation(args: argparse.Namespace) -> int:
    provider_store = ProviderStore()
    provider = _require_provider(provider_store, args.provider_id)
    provider.rotation_enabled = bool(args.enable)
    provider_store.update(provider)
    data = {"provider": _provider_summary(provider)}
    if args.json:
        _print_json(data)
        return 0
    state = "enabled" if provider.rotation_enabled else "disabled"
    print(f"Provider rotation {state}: {provider.id}")
    return 0


def _provider_node(args: argparse.Namespace) -> int:
    provider = _require_provider(ProviderStore(), args.provider_id)
    profile_store = ProfileStore()
    profile = _require_profile(profile_store, args.node_id)
    if profile.provider_id != provider.id:
        raise ParseError(f"node does not belong to provider: {args.node_id}")
    profile.in_rotation_pool = bool(args.enable)
    profile_store.update(profile)
    data = {
        "provider": _provider_summary(provider),
        "node": _profile_summary(profile),
    }
    if args.json:
        _print_json(data)
        return 0
    state = "enabled" if profile.in_rotation_pool else "disabled"
    print(f"Provider node rotation {state}: {profile.id}")
    return 0


def _node_group_list(args: argparse.Namespace) -> int:
    groups = NodeGroupStore().list()
    data = [_node_group_summary(group) for group in groups]
    if args.json:
        _print_json(data)
        return 0
    if not groups:
        print("No node groups found.")
        return 0
    print("Name\tEnabled\tMode\tManual\tProfiles\tProviders\tExcluded\tPolicy")
    for item in data:
        print(
            "\t".join(
                [
                    str(item["name"]),
                    _on_off(bool(item["enabled"])),
                    str(item["selection_mode"]),
                    str(item["manual_profile_id"] or "-"),
                    str(len(item["member_profile_ids"])),
                    str(len(item["member_provider_ids"])),
                    str(len(item["exclude_profile_ids"])),
                    str(item["resilience_policy"]),
                ]
            )
        )
    return 0


def _node_group_create(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    if store.get(args.name) is not None:
        raise ParseError(
            f"node group already exists: {args.name}; run `watchdog node-group list` to inspect node groups"
        )
    group = NodeGroup(name=args.name)
    backup_path = _create_section_backup("node-groups")
    store.add(group)
    data = {
        "group": _node_group_summary(group),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Created node group: {group.name}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_add_profile(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    profile = _require_profile(ProfileStore(), args.profile)
    backup_path = _create_section_backup("node-groups")
    group = store.add_member_profile(args.group, profile.id)
    data = {
        "group": _node_group_summary(group),
        "added_profile_id": profile.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Added profile to node group: {group.name} profile={profile.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_select(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    backup_path = None
    if args.selection == "auto":
        backup_path = _create_section_backup("node-groups")
        group = store.set_selection(args.group, NodeGroupSelectionMode.AUTO)
        data = {
            "group": _node_group_summary(group),
            "selection": "auto",
            "backup_path": str(backup_path),
            "rollback_point": _section_backup_rollback("node-groups", backup_path),
        }
        if args.json:
            _print_json(data)
            return 0
        print(f"Node group selection set to auto: {group.name}")
        print(f"Backup: {backup_path}")
        return 0
    profile = _require_profile(ProfileStore(), args.selection)
    backup_path = _create_section_backup("node-groups")
    group = store.set_selection(args.group, NodeGroupSelectionMode.MANUAL, profile.id)
    data = {
        "group": _node_group_summary(group),
        "selection": "manual",
        "selected_profile_id": profile.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Node group selection pinned: {group.name} profile={profile.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_add_provider(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    provider = _require_provider(ProviderStore(), args.provider)
    backup_path = _create_section_backup("node-groups")
    group = store.add_member_provider(args.group, provider.id)
    data = {
        "group": _node_group_summary(group),
        "added_provider_id": provider.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Added provider to node group: {group.name} provider={provider.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_remove_provider(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    provider = _require_provider(ProviderStore(), args.provider)
    backup_path = _create_section_backup("node-groups")
    group = store.remove_member_provider(args.group, provider.id)
    data = {
        "group": _node_group_summary(group),
        "removed_provider_id": provider.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Removed provider from node group: {group.name} provider={provider.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_exclude(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    profile = _require_profile(ProfileStore(), args.profile)
    backup_path = _create_section_backup("node-groups")
    group = store.add_exclude_profile(args.group, profile.id)
    data = {
        "group": _node_group_summary(group),
        "excluded_profile_id": profile.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Excluded profile from node group: {group.name} profile={profile.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_unexclude(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    profile = _require_profile(ProfileStore(), args.profile)
    backup_path = _create_section_backup("node-groups")
    group = store.remove_exclude_profile(args.group, profile.id)
    data = {
        "group": _node_group_summary(group),
        "unexcluded_profile_id": profile.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Removed profile from node group exclusion list: {group.name} profile={profile.id}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_set_resilience(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    policy = NodeGroupResiliencePolicy(args.policy)
    backup_path = _create_section_backup("node-groups")
    group = store.set_resilience_policy(args.group, policy)
    data = {
        "group": _node_group_summary(group),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Node group resilience policy set: {group.name} policy={policy.value}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_set_enabled(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    backup_path = _create_section_backup("node-groups")
    group = store.set_enabled(args.group, bool(args.enabled))
    data = {
        "group": _node_group_summary(group),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("node-groups", backup_path),
    }
    if args.json:
        _print_json(data)
        return 0
    print(f"Node group {'enabled' if group.enabled else 'disabled'}: {group.name}")
    print(f"Backup: {backup_path}")
    return 0


def _node_group_auto_test(args: argparse.Namespace) -> int:
    response = WatchdogIPCClient().node_group_auto_test(args.group)
    if not response.ok:
        _error(response.error or "node-group auto-test failed")
        return 70
    data = response.payload
    if args.json:
        _print_json(data)
        return 0
    _print_node_group_auto_test(data)
    return 0


def _config_set(args: argparse.Namespace) -> int:
    if args.key == "mode":
        return _config_set_mode_value(args.value, args.json)
    if args.key in {"routing-policy", "capture-modes", "default-route-action"}:
        return _config_set_routing_value(args.key, args.value, args.json)
    if args.key.startswith("dns."):
        return _config_set_dns_value(args.key, args.value, args.json)
    if args.key not in CONFIG_SET_KEYS:
        supported = ", ".join(
            [
                "mode",
                "routing-policy",
                "capture-modes",
                "default-route-action",
                *sorted(DNS_POLICY_SET_KEYS),
                *sorted(CONFIG_SET_KEYS),
            ]
        )
        raise ParseError(f"unsupported config key: {args.key} (supported: {supported})")

    config_store = AppConfig()
    config = config_store.load()
    section, key = args.key.split(".", 1)
    value = _parse_config_value(args.key, args.value)
    config.setdefault(section, {})[key] = value
    config_store.save(config)
    data = {"key": args.key, "value": config_store.load()[section][key]}
    warning = _lan_sharing_warning(args.key, data["value"])
    if warning is not None:
        data["warning"] = warning
    if args.json:
        _print_json(data)
    else:
        if warning is not None:
            print(f"Warning: {warning}", file=sys.stderr)
        print(f"Config set: {args.key}={data['value']}")
    return 0


def _lan_sharing_warning(key: str, value: object) -> str | None:
    if key == "lan_sharing.enabled" and value is True:
        mode = str(AppConfig().load().get("lan_sharing", {}).get("mode", "disabled"))
        if mode == "gateway":
            return (
                "LAN gateway is enabled for the next runtime apply; it may enable "
                "temporary IPv4 forwarding and WatchdogVPN-owned NAT/firewall rules "
                "for the configured interface in VM/lab-validated environments only."
            )
        return (
            "LAN sharing is enabled for the next runtime apply; it exposes authenticated "
            "SOCKS/HTTP listeners on the configured bind address and does not apply "
            "firewall rules automatically in Task 20.3."
        )
    return None


def _config_lan_sharing_credentials(args: argparse.Namespace) -> int:
    config_store = AppConfig()
    config = config_store.load()
    lan_config = config.get("lan_sharing", {})
    enabled = bool(lan_config.get("enabled", False))
    data: dict[str, object] = {
        "enabled": enabled,
        "username": None,
        "password_available": False,
        "secret_included": False,
    }
    if enabled:
        credentials = load_or_create_lan_sharing_credentials(
            lan_sharing_credentials_path(config_store.path)
        )
        data["username"] = credentials["username"]
        data["password_available"] = True
        if args.show_secret:
            data["password"] = credentials["password"]
            data["secret_included"] = True
    if args.json:
        _print_json(data)
        return 0
    print(f"LAN sharing enabled: {'yes' if enabled else 'no'}")
    if not enabled:
        print("Credentials: not created")
        return 0
    print(f"Username: {data['username']}")
    if args.show_secret:
        print(f"Password: {data['password']}")
    else:
        print("Password: available; rerun with --show-secret to print it")
    return 0


def _config_set_routing_value(key: str, value: str, json_output: bool) -> int:
    manager = StateManager()
    state = manager.load()
    if key == "routing-policy":
        if value not in ALLOWED_ROUTING_POLICIES:
            supported = ", ".join(sorted(ALLOWED_ROUTING_POLICIES))
            raise ParseError(f"routing-policy must be one of: {supported}")
        state["routing_policy"] = value
    elif key == "capture-modes":
        modes = parse_capture_modes(value)
        state["capture_modes"] = ",".join(modes)
    elif key == "default-route-action":
        if value not in ALLOWED_DEFAULT_ROUTE_ACTIONS:
            supported = ", ".join(sorted(ALLOWED_DEFAULT_ROUTE_ACTIONS))
            raise ParseError(f"default-route-action must be one of: {supported}")
        state["default_route_action"] = value
    else:  # pragma: no cover - guarded by caller
        raise ParseError(f"unsupported routing key: {key}")
    manager.save(state)
    data = _routing_state_data(manager.load())
    if json_output:
        _print_json(data)
    else:
        print("Routing state updated.")
        _print_routing_state_summary(data)
    return 0


def _config_set_dns_value(key: str, value: str, json_output: bool) -> int:
    if key not in DNS_POLICY_SET_KEYS:
        supported = ", ".join(sorted(DNS_POLICY_SET_KEYS))
        raise ParseError(f"unsupported dns config key: {key} (supported: {supported})")
    field_name = key.split(".", 1)[1]
    store = DNSPolicyStore()
    policy = store.load()
    parsed: object
    if key in DNS_POLICY_BOOL_SET_KEYS:
        lowered = value.lower()
        if lowered == "true":
            parsed = True
        elif lowered == "false":
            parsed = False
        else:
            raise ParseError(f"{key} must be true or false")
    elif key == "dns.ecs_direct_subnet" and value.lower() in {"none", "null", ""}:
        parsed = None
    else:
        parsed = value
    setattr(policy, field_name, parsed)
    policy = DNSPolicy.from_dict(policy.to_dict())
    mutation_data = _save_dns_policy_mutation(store, policy)
    data = {
        "key": key,
        "value": getattr(policy, field_name),
        "backup_path": mutation_data["backup_path"],
        "rollback_point": mutation_data["rollback_point"],
    }
    if json_output:
        _print_json(data)
    else:
        print(f"Config set: {key}={data['value']}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _config_set_mode_value(mode: str, json_output: bool) -> int:
    if mode not in ALLOWED_ACTIVE_MODES:
        supported = ", ".join(sorted(ALLOWED_ACTIVE_MODES))
        raise ParseError(f"mode must be one of: {supported}")
    manager = StateManager()
    manager.set("active_mode", mode)
    state = manager.load()
    data = _routing_state_data(state)
    if json_output:
        _print_json(data)
    else:
        print(f"Active mode set to: {state['active_mode']}")
        print(
            "Compatibility alias: routing_policy="
            f"{state['routing_policy']} capture_modes={state['capture_modes']} "
            f"default_route_action={state['default_route_action']}"
        )
    return 0


def _config_routing_contract(args: argparse.Namespace) -> int:
    state = StateManager().load()
    data = {
        "current": _routing_state_data(state),
        "contract": {
            "routing_policies": sorted(ALLOWED_ROUTING_POLICIES),
            "route_actions": sorted(ALLOWED_DEFAULT_ROUTE_ACTIONS),
            "capture_modes": [
                {
                    "capture_modes": list(modes),
                    "connectable": capture_modes_connectable(modes),
                    "status": "connectable" if capture_modes_connectable(modes) else "representable-fail-closed",
                    "reason": (
                        "supported by current runtime"
                        if capture_modes_connectable(modes)
                        else "system_proxy is representable but runtime remains fail-closed"
                    ),
                }
                for modes in [
                    ("local_proxy",),
                    ("local_proxy", "tun"),
                    ("local_proxy", "system_proxy"),
                    ("local_proxy", "tun", "system_proxy"),
                ]
            ],
            "invalid_capture_modes": [
                {
                    "capture_modes": [],
                    "reason": "at least one capture mode is required",
                },
                {
                    "capture_modes": ["system_proxy"],
                    "reason": "system_proxy requires local_proxy",
                },
                {
                    "capture_modes": ["tun", "system_proxy"],
                    "reason": "system_proxy requires local_proxy",
                },
            ],
            "notes": [
                "direct is a route action, not a capture mode",
                "global ignores route rules and uses default_route_action for captured traffic",
                "rule evaluates route rules and falls back to default_route_action on no match",
                "LAN proxy sharing and LAN gateway/router mode belong to Phase 20",
            ],
        },
    }
    if args.json:
        _print_json(data)
    else:
        _print_routing_state_summary(data["current"])
        print("Capture coexistence:")
        for item in data["contract"]["capture_modes"]:
            print(
                "  "
                f"{','.join(item['capture_modes'])}: {item['status']} - {item['reason']}"
            )
        print("Invalid capture examples:")
        for item in data["contract"]["invalid_capture_modes"]:
            rendered = ",".join(item["capture_modes"]) or "<none>"
            print(f"  {rendered}: {item['reason']}")
    return 0


def _routing_state_data(state: dict[str, object]) -> dict[str, object]:
    modes = parse_capture_modes(str(state["capture_modes"]))
    return {
        "active_mode": state["active_mode"],
        "active_mode_role": "compatibility-display-only",
        "routing_state_version": state["routing_state_version"],
        "routing_policy": state["routing_policy"],
        "capture_modes": list(modes),
        "default_route_action": state["default_route_action"],
        "connectable": capture_modes_connectable(modes),
        "runtime_status": "connectable" if capture_modes_connectable(modes) else "representable-fail-closed",
    }


def _print_routing_state_summary(data: dict[str, object]) -> None:
    print(f"Routing policy: {data['routing_policy']}")
    print(f"Capture modes: {','.join(str(item) for item in data['capture_modes'])}")
    print(f"Default route action: {data['default_route_action']}")
    print(f"Runtime status: {data['runtime_status']}")
    print("Compatibility active_mode: display only")


def _parse_config_value(key: str, value: str) -> bool | int | str:
    if key == "rotation.scheduled_interval_hours" and value == "off":
        return 0
    if key in CONFIG_BOOL_SET_KEYS:
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        raise ParseError(f"{key} must be true or false")
    if key in CONFIG_INT_SET_KEYS:
        try:
            return int(value)
        except ValueError as exc:
            raise ParseError(f"{key} must be an integer") from exc
    return value


def _stats_status(args: argparse.Namespace) -> int:
    data = _metrics_status_data(MetricsStore())
    if args.json:
        _print_json(data)
        return 0
    _print_metrics_status(data)
    return 0


def _stats_summary(args: argparse.Namespace) -> int:
    data = _metrics_summary_data(MetricsStore())
    if args.json:
        _print_json(data)
        return 0
    _print_metrics_status(data["status"])
    print(f"Total events: {data['total_events']}")
    print(f"Withheld counter keys: {data['withheld_counter_keys']}")
    counters = data["counters"]
    if not isinstance(counters, dict) or not counters:
        print("Counters: none")
        return 0
    print("Counters:")
    for key, value in counters.items():
        print(f"  {key}: {value}")
    return 0


def _stats_purge(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ParseError("stats purge requires --yes")
    purged = MetricsStore().purge()
    data = {
        "purged": purged,
        "metrics_status": "removed" if purged else "absent",
        "history_included": False,
        "detailed_history_supported": False,
    }
    if args.json:
        _print_json(data)
        return 0
    print("Metrics purged." if purged else "Metrics already absent.")
    return 0


def _stats_privacy_mode(args: argparse.Namespace) -> int:
    mode = MetricsRedactionMode(args.mode)
    store = MetricsStore()
    current = store.load()
    enabled = mode != MetricsRedactionMode.OFF
    updated = MetricsDocument(
        schema_version=current.schema_version,
        enabled=enabled,
        retention_days=current.retention_days,
        redaction_mode=mode,
        max_bytes=current.max_bytes,
        buckets=current.buckets,
        updated_at=current.updated_at,
    )
    store.save(updated)
    data = _metrics_status_data(store)
    data["history_included"] = False
    if args.json:
        _print_json(data)
        return 0
    print(f"Metrics privacy mode: {mode.value}")
    print(f"Metrics enabled: {_on_off(enabled)}")
    if mode == MetricsRedactionMode.DETAILED:
        print("Detailed request history is not implemented; aggregate counters remain the only recorded data.")
    return 0


def _metrics_status_data(store: MetricsStore) -> dict[str, object]:
    exists = store.path.exists()
    document = store.load()
    total_events, _ = _metrics_counter_totals(document)
    return {
        "metrics_status": "available" if exists else "missing",
        "enabled": document.enabled,
        "redaction_mode": document.redaction_mode.value,
        "retention_days": document.retention_days,
        "max_bytes": document.max_bytes,
        "bucket_count": len(document.buckets),
        "total_events": total_events,
        "updated_at": document.updated_at,
        "detailed_history_supported": False,
    }


def _metrics_summary_data(store: MetricsStore) -> dict[str, object]:
    document = store.load()
    total_events, counters = _metrics_counter_totals(document)
    visible_counters = {
        key: value
        for key, value in counters.items()
        if key.startswith(VISIBLE_STATS_COUNTER_PREFIXES)
    }
    buckets = [
        {
            "bucket_start": bucket.bucket_start,
            "bucket_end": bucket.bucket_end,
            "total_events": sum(bucket.counters.values()),
            "counter_count": len(bucket.counters),
        }
        for bucket in document.buckets
    ]
    return {
        "status": _metrics_status_data(store),
        "total_events": total_events,
        "counters": dict(sorted(visible_counters.items())),
        "withheld_counter_keys": len(counters) - len(visible_counters),
        "buckets": buckets,
    }


def _metrics_counter_totals(document: MetricsDocument) -> tuple[int, dict[str, int]]:
    counters: dict[str, int] = {}
    total_events = 0
    for bucket in document.buckets:
        for key, value in bucket.counters.items():
            total_events += value
            counters[key] = counters.get(key, 0) + value
    return total_events, dict(sorted(counters.items()))


def _print_metrics_status(data: dict[str, object]) -> None:
    print(f"Metrics: {data['metrics_status']}")
    print(f"Enabled: {_on_off(bool(data['enabled']))}")
    print(f"Privacy mode: {data['redaction_mode']}")
    print(f"Retention days: {data['retention_days']}")
    print(f"Buckets: {data['bucket_count']}")
    print(f"Detailed history supported: {_on_off(bool(data['detailed_history_supported']))}")


def _rules_explain(args: argparse.Namespace) -> int:
    traffic = TrafficInfo(
        domain=args.domain,
        ip=args.ip,
        port=args.port,
        protocol=args.protocol,
        network=args.network,
        process_name=args.process_name,
        process_path=args.process_path,
    )
    trust_path = Path(args.ruleset_trust_file) if args.ruleset_trust_file else None
    trust_registry = RuleSetTrustStore(trust_path).load()
    rule_groups = RuleStore().list_groups()
    routing_state = StateManager().load()
    app_policy = AppPolicyStore().load_or_disabled().policy
    diagnostic = diagnose_route(
        traffic=traffic,
        rule_groups=rule_groups,
        routing_state=routing_state,
        trust_registry=trust_registry,
        app_policy=app_policy,
    )
    chain_diagnostic = _chain_diagnostic_for_action(
        diagnostic.route_action,
        dns_policy=DNSPolicyStore().load(),
    )
    if chain_diagnostic is not None:
        diagnostic = diagnose_route(
            traffic=traffic,
            rule_groups=rule_groups,
            routing_state=routing_state,
            trust_registry=trust_registry,
            app_policy=app_policy,
            chain_diagnostic=chain_diagnostic,
        )
    if args.json:
        _print_json(diagnostic.to_dict())
    else:
        _print_route_diagnostic(diagnostic)
    return 0


def _rules_list(args: argparse.Namespace) -> int:
    groups = RuleStore().list_groups()
    data = [_rule_group_summary(group) for group in groups]
    if args.json:
        _print_json(data)
        return 0
    if not groups:
        print("No rule groups found.")
        return 0
    print("Name\tEnabled\tPriority\tRules")
    for group in groups:
        print(
            "\t".join(
                [
                    group.name,
                    _on_off(group.enabled),
                    str(group.priority),
                    str(len(group.rules)),
                ]
            )
        )
    return 0


def _rules_set_group_enabled(args: argparse.Namespace) -> int:
    store = RuleStore()
    existing = store.get_group(args.group)
    if existing is None:
        raise RuleStoreError(
            f"rule group not found: {args.group}; run `watchdog rules list` to inspect rule groups"
        )
    backup_path = store.replace_group(existing, backup_existing=True)
    if args.enabled:
        store.enable_group(args.group)
    else:
        store.disable_group(args.group)
    group = store.get_group(args.group)
    if group is None:
        raise RuleStoreError(f"rule group not found: {args.group}")
    data = {
        "group": group.to_dict(),
        "backup_path": str(backup_path) if backup_path else None,
        "rollback_point": _group_backup_rollback("routing-rules", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Rule group {'enabled' if group.enabled else 'disabled'}: {group.name}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _rules_add_rule(args: argparse.Namespace) -> int:
    store = RuleStore()
    existing = store.get_group(args.group)
    if existing is None:
        raise RuleStoreError(
            f"rule group not found: {args.group}; run `watchdog rules list` to inspect rule groups"
        )
    try:
        rule = Rule(
            id=args.rule_id,
            action=args.action,
            conditions=_parse_rule_conditions(args.condition),
        )
    except ValueError as exc:
        raise ParseError(str(exc)) from exc
    if any(existing_rule.id == rule.id for existing_rule in existing.rules):
        raise RuleStoreError(
            f"rule already exists: {rule.id}; run `watchdog rules export {args.group} --json` to inspect rules"
        )
    backup_path = store.replace_group(existing, backup_existing=True)
    group = store.add_rule(args.group, rule)
    data = {
        "added": rule.to_dict(),
        "group": group.to_dict(),
        "backup_path": str(backup_path) if backup_path else None,
        "rollback_point": _group_backup_rollback("routing-rules", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Added rule: {group.name}/{rule.id}")
        print(f"Action: {rule.action}")
        print(f"Conditions: {_format_rule_conditions(rule.conditions)}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _rules_remove_rule(args: argparse.Namespace) -> int:
    store = RuleStore()
    existing = store.get_group(args.group)
    if existing is None:
        raise RuleStoreError(
            f"rule group not found: {args.group}; run `watchdog rules list` to inspect rule groups"
        )
    if not any(rule.id == args.rule_id for rule in existing.rules):
        raise RuleStoreError(
            f"rule not found: {args.rule_id}; run `watchdog rules export {args.group} --json` to inspect rules"
        )
    backup_path = store.replace_group(existing, backup_existing=True)
    group = store.remove_rule(args.group, args.rule_id)
    data = {
        "removed": args.rule_id,
        "group": group.to_dict(),
        "backup_path": str(backup_path) if backup_path else None,
        "rollback_point": _group_backup_rollback("routing-rules", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Removed rule: {group.name}/{args.rule_id}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _rules_set_priority(args: argparse.Namespace) -> int:
    store = RuleStore()
    existing = store.get_group(args.group)
    if existing is None:
        raise RuleStoreError(
            f"rule group not found: {args.group}; run `watchdog rules list` to inspect rule groups"
        )
    backup_path = store.replace_group(existing, backup_existing=True)
    group = store.set_priority(args.group, args.priority)
    data = {
        "group": group.to_dict(),
        "backup_path": str(backup_path) if backup_path else None,
        "rollback_point": _group_backup_rollback("routing-rules", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Rule group priority set: {group.name} priority={group.priority}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _rules_set_rule_enabled(args: argparse.Namespace) -> int:
    store = RuleStore()
    existing = store.get_group(args.group)
    if existing is None:
        raise RuleStoreError(
            f"rule group not found: {args.group}; run `watchdog rules list` to inspect rule groups"
        )
    if not any(rule.id == args.rule_id for rule in existing.rules):
        raise RuleStoreError(
            f"rule not found: {args.rule_id}; run `watchdog rules export {args.group} --json` to inspect rules"
        )
    backup_path = store.replace_group(existing, backup_existing=True)
    group = store.set_rule_enabled(args.group, args.rule_id, bool(args.enabled))
    data = {
        "group": group.to_dict(),
        "rule_id": args.rule_id,
        "enabled": bool(args.enabled),
        "backup_path": str(backup_path) if backup_path else None,
        "rollback_point": _group_backup_rollback("routing-rules", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        state = "enabled" if args.enabled else "disabled"
        print(f"Rule {state}: {group.name}/{args.rule_id}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _rules_import(args: argparse.Namespace) -> int:
    source = Path(args.file)
    try:
        plan = build_rule_import_plan(
            source,
            name=args.name,
            default_action=args.default_action,
            allow_partial=bool(args.allow_partial),
        )
    except RuleImportError as exc:
        raise ParseError(str(exc)) from exc
    group = plan.group

    store = RuleStore()
    existing = store.get_group(group.name)
    if existing is not None and not args.replace:
        raise RuleStoreError(
            f"rule group already exists: {group.name}; use --replace to overwrite"
        )
    backup_path = None
    section_backup_path = None
    if not args.dry_run:
        section_backup_path = _create_section_backup("routing-rules")
        backup_path = store.replace_group(group, backup_existing=bool(existing and args.replace))
    if args.dry_run:
        rollback_point = {"kind": "preview-only"}
    elif backup_path:
        rollback_point = {"kind": "existing-group-backup", "path": str(backup_path)}
    else:
        rollback_point = {"kind": "new-group-delete", "group": group.name}
    data = {
        "dry_run": bool(args.dry_run),
        "source_format": plan.source_format,
        "imported": group.to_dict(),
        "replaced": existing is not None,
        "backup_path": str(backup_path) if backup_path else None,
        "section_backup_path": str(section_backup_path) if section_backup_path else None,
        "rollback_point": rollback_point,
        "accepted_rule_count": len(group.rules),
        "rejected": [item.to_dict() for item in plan.rejected],
        "warnings": list(plan.warnings),
    }
    if args.json:
        _print_json(data)
    else:
        verb = "Would import" if args.dry_run else "Imported"
        print(f"{verb} rule group: {group.name}")
        print(f"Source format: {plan.source_format}")
        print(f"Accepted rules: {len(group.rules)}")
        if plan.rejected:
            print(f"Rejected entries: {len(plan.rejected)}")
        if backup_path:
            print(f"Backup: {backup_path}")
        if section_backup_path:
            print(f"Section backup: {section_backup_path}")
        if not args.dry_run and not backup_path:
            print(f"Rollback: remove imported group {group.name}")
    return 0


def _rules_export(args: argparse.Namespace) -> int:
    group = RuleStore().get_group(args.group)
    if group is None:
        raise RuleStoreError(f"rule group not found: {args.group}")
    data = group.to_dict()
    if args.output:
        target = Path(args.output)
        dump_json(target, data)
        if args.json:
            _print_json({"group": data, "output": str(target)})
        else:
            print(f"Exported rule group: {group.name}")
            print(f"Output: {target}")
        return 0
    if args.json:
        _print_json(data)
        return 0
    raise ParseError("rules export requires --output or --json")


def _ruleset_status(args: argparse.Namespace) -> int:
    registry = RuleSetLifecycleManager().status()
    data = registry.to_dict()
    if args.json:
        _print_json(data)
        return 0
    if not registry.policies:
        print("No trusted rule sets configured.")
        return 0
    print("ID\tKind\tCritical\tBehavior\tState\tCache")
    for rule_set_id, policy in sorted(registry.policies.items()):
        status = registry.status_for(rule_set_id)
        print(
            "\t".join(
                [
                    rule_set_id,
                    policy.kind.value,
                    _on_off(policy.critical),
                    policy.failure_behavior.value,
                    status.state.value,
                    status.cache_path or "-",
                ]
            )
        )
    return 0


def _ruleset_refresh(args: argparse.Namespace) -> int:
    if args.ids and args.referenced_only:
        raise ParseError("ruleset refresh accepts IDs or --referenced-only, not both")
    if args.referenced_only:
        selected = referenced_rule_set_ids(RuleStore().list_groups())
    elif args.ids:
        selected = set(args.ids)
    else:
        selected = None
    results = RuleSetLifecycleManager().refresh(
        selected,
        force=bool(args.force),
        evict=not bool(args.no_evict),
    )
    data = {
        "refreshed_count": sum(1 for result in results if result.refreshed),
        "used_existing_cache_count": sum(1 for result in results if result.used_existing_cache),
        "results": [result.to_dict() for result in results],
    }
    if args.json:
        _print_json(data)
        return 0
    if not results:
        print("No rule sets selected.")
        return 0
    print("ID\tState\tRefreshed\tCache\tError")
    for result in results:
        print(
            "\t".join(
                [
                    result.id,
                    result.state,
                    _on_off(result.refreshed),
                    result.cache_path or "-",
                    result.error or "-",
                ]
            )
        )
    return 0


def _ruleset_add(args: argparse.Namespace) -> int:
    store = RuleSetTrustStore()
    kwargs: dict[str, object] = {
        "id": args.id,
        "kind": args.kind,
        "source": args.source,
    }
    if args.sha256 is not None:
        kwargs["expected_sha256"] = args.sha256
    if args.critical is not None:
        kwargs["critical"] = args.critical
    if args.update_interval_seconds is not None:
        kwargs["update_interval_seconds"] = args.update_interval_seconds
    if args.max_stale_seconds is not None:
        kwargs["max_stale_seconds"] = args.max_stale_seconds
    if args.failure_behavior is not None:
        kwargs["failure_behavior"] = args.failure_behavior
    try:
        policy = RuleSetTrustPolicy(**kwargs)
    except ValueError as exc:
        raise ParseError(str(exc)) from exc
    backup_path = store.add(policy)
    data = {
        "policy": policy.to_dict(),
        "backup_path": str(backup_path) if backup_path else None,
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Rule-set trust policy added: {policy.id}")
        print(f"Kind: {policy.kind.value}")
        print(f"Failure behavior: {policy.failure_behavior.value}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _ruleset_remove(args: argparse.Namespace) -> int:
    store = RuleSetTrustStore()
    backup_path = store.remove(args.id)
    data = {
        "removed": args.id,
        "backup_path": str(backup_path) if backup_path else None,
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Rule-set trust policy removed: {args.id}")
        if backup_path:
            print(f"Backup: {backup_path}")
    return 0


def _require_chain(store: RouteChainStore, chain_id: str) -> RouteChain:
    chain = store.get(chain_id)
    if chain is None:
        raise ParseError(
            f"route chain not found: {chain_id}; run `watchdog chain list` to inspect route chains"
        )
    return chain


def _parse_chain_hop_spec(spec: str) -> ChainHop:
    hop_type, sep, target = spec.partition(":")
    if not sep:
        raise ParseError(f"invalid --hop value, expected TYPE:TARGET: {spec}")
    normalized_type = hop_type.strip()
    selection_policy = "group_policy" if normalized_type == ChainHopType.GROUP.value else None
    return ChainHop(
        type=normalized_type,
        target=target.strip(),
        selection_policy=selection_policy,
    )


def _chain_summary(chain: RouteChain) -> dict:
    return chain.to_dict()


def _validate_chain_hop_targets(hops: list[ChainHop]) -> None:
    profile_store = ProfileStore()
    node_group_store = NodeGroupStore()
    for hop in hops:
        if hop.type == ChainHopType.PROFILE:
            _require_profile(profile_store, hop.target)
        elif hop.type == ChainHopType.GROUP:
            _require_node_group(node_group_store, hop.target)


def _updated_chain(
    chain: RouteChain,
    *,
    hops: list[ChainHop] | None = None,
    enabled: bool | None = None,
) -> RouteChain:
    data = chain.to_dict()
    if hops is not None:
        data["hops"] = [hop.to_dict() for hop in hops]
    if enabled is not None:
        data["enabled"] = enabled
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    return RouteChain.from_dict(data)


def _chain_list(args: argparse.Namespace) -> int:
    chains = RouteChainStore().list()
    data = [_chain_summary(chain) for chain in chains]
    if args.json:
        _print_json(data)
        return 0
    if not chains:
        print("No route chains found.")
        return 0
    print("ID\tEnabled\tHops\tDescription")
    for chain in chains:
        print(
            "\t".join(
                [
                    chain.id,
                    _on_off(chain.enabled),
                    str(len(chain.hops)),
                    chain.description or "-",
                ]
            )
        )
    return 0


def _chain_show(args: argparse.Namespace) -> int:
    chain = _require_chain(RouteChainStore(), args.id)
    data = _chain_summary(chain)
    if args.json:
        _print_json(data)
        return 0
    print(f"Chain: {chain.id}")
    print(f"Enabled: {_on_off(chain.enabled)}")
    print(f"Description: {chain.description or '-'}")
    print("Hops:")
    for index, hop in enumerate(chain.hops, start=1):
        extra = f" selection_policy={hop.selection_policy}" if hop.selection_policy else ""
        print(f"  {index}. {hop.type.value}:{hop.target}{extra}")
    return 0


def _chain_create(args: argparse.Namespace) -> int:
    store = RouteChainStore()
    if store.get(args.id) is not None:
        raise ParseError(
            f"route chain already exists: {args.id}; run `watchdog chain show {args.id}` to inspect it"
        )
    hops = [_parse_chain_hop_spec(spec) for spec in args.hop]
    _validate_chain_hop_targets(hops)
    created_at = datetime.now(timezone.utc).isoformat()
    chain = RouteChain(
        id=args.id,
        hops=hops,
        description=args.description,
        created_at=created_at,
        updated_at=created_at,
    )
    backup_path = _create_section_backup("route-chains")
    store.add(chain)
    data = {
        "chain": _chain_summary(chain),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("route-chains", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Created route chain: {chain.id} (disabled; run `watchdog chain enable {chain.id}` when ready)")
        print(f"Backup: {backup_path}")
    return 0


def _chain_add_hop(args: argparse.Namespace) -> int:
    store = RouteChainStore()
    chain = _require_chain(store, args.id)
    new_hop = ChainHop(type=args.type, target=args.target, selection_policy=args.selection_policy)
    _validate_chain_hop_targets([new_hop])
    updated = _updated_chain(chain, hops=[*chain.hops, new_hop])
    backup_path = _create_section_backup("route-chains")
    store.add(updated)
    data = {
        "chain": _chain_summary(updated),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("route-chains", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Added hop to route chain: {chain.id} {args.type}:{args.target}")
        print(f"Backup: {backup_path}")
    return 0


def _chain_remove_hop(args: argparse.Namespace) -> int:
    store = RouteChainStore()
    chain = _require_chain(store, args.id)
    if args.index < 1 or args.index > len(chain.hops):
        raise ParseError(
            f"chain hop index out of range: {args.index}; run `watchdog chain show {chain.id}` to inspect hops"
        )
    if len(chain.hops) == 1:
        raise ParseError(
            f"cannot remove the last hop from route chain: {chain.id}; "
            f"run `watchdog chain remove {chain.id}` to remove the whole chain instead"
        )
    remaining = [hop for position, hop in enumerate(chain.hops, start=1) if position != args.index]
    updated = _updated_chain(chain, hops=remaining)
    backup_path = _create_section_backup("route-chains")
    store.add(updated)
    data = {
        "chain": _chain_summary(updated),
        "removed_index": args.index,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("route-chains", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Removed hop {args.index} from route chain: {chain.id}")
        print(f"Backup: {backup_path}")
    return 0


def _chain_set_enabled(args: argparse.Namespace) -> int:
    store = RouteChainStore()
    chain = _require_chain(store, args.id)
    if args.enabled:
        _validate_chain_hop_targets(chain.hops)
    updated = _updated_chain(chain, enabled=bool(args.enabled))
    backup_path = _create_section_backup("route-chains")
    store.add(updated)
    data = {
        "chain": _chain_summary(updated),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("route-chains", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        state = "enabled" if updated.enabled else "disabled"
        print(f"Route chain {state}: {chain.id}")
        print(f"Backup: {backup_path}")
    return 0


def _chain_remove(args: argparse.Namespace) -> int:
    store = RouteChainStore()
    _require_chain(store, args.id)
    backup_path = _create_section_backup("route-chains")
    store.remove(args.id)
    data = {
        "removed": args.id,
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("route-chains", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Removed route chain: {args.id}")
        print(f"Backup: {backup_path}")
    return 0


def _print_route_diagnostic(diagnostic: RouteDiagnostic) -> None:
    data = diagnostic.to_dict()
    routing = data["routing"]
    confidence = RuleExplanationConfidence(data["confidence"])

    print("Route diagnostic: configured policy only, not live traffic observation.")
    print(f"Routing policy: {routing['routing_policy']}")
    print(f"Capture modes: {','.join(routing['capture_modes'])}")
    print(f"Default route action: {routing['default_route_action']}")
    print("Compatibility active_mode: display only")
    print(f"Confidence: {confidence.value}")
    print(f"Input: {_format_rule_explain_input(data['input_traffic'])}")

    route_action = data.get("route_action") or "unknown"
    if confidence == RuleExplanationConfidence.DEFINITIVE and route_action != "unknown":
        print(f"Decision: configured policy would use action '{route_action}'.")
    elif confidence == RuleExplanationConfidence.PARTIAL:
        print("Decision: incomplete; more input is needed before stating a final action.")
        if route_action != "unknown":
            print(f"Candidate local action: {route_action}")
    elif confidence == RuleExplanationConfidence.RUNTIME_REQUIRED:
        print("Decision: cannot be determined statically.")
        print("Reason: runtime-evaluated rule sets may change the result.")
        if route_action != "unknown":
            print(f"Candidate local action: {route_action}")
    else:
        print("Decision: unknown; provide a domain, IP, port, protocol, network, or process.")

    if data["rule_evaluation"] == "ignored-by-global-policy":
        print("Rule evaluation: ignored by global routing policy.")
    else:
        print("Rule evaluation: enabled by rule routing policy.")

    status = data["route_action_status"]
    if status == "applies":
        print(f"Route action: {route_action}")
    elif status == "candidate":
        print(f"Candidate route action: {route_action}")
    else:
        print("Route action: unknown")

    source = data.get("route_source")
    if isinstance(source, dict):
        if source.get("source") == "rule":
            print(f"Matched rule: {source.get('group_name')}/{source.get('rule_id')}")
        elif source.get("source") == "final":
            print("Matched rule: none; default route action applies.")
        elif source.get("source") == "app-policy":
            print("Matched policy: app-policy")
        elif source.get("source") == "routing-policy":
            print("Matched policy: global routing policy")

    if data.get("no_rule_match") is True:
        print("No configured route rule matched.")

    if diagnostic.chain_diagnostic is not None:
        print("Chain diagnostic:")
        for line in diagnostic.chain_diagnostic.to_human_lines():
            print(f"  {line}")

    skipped = data.get("skipped_conditions", [])
    if isinstance(skipped, list) and skipped:
        print("Skipped conditions:")
        for item in skipped:
            if not isinstance(item, dict):
                continue
            print(
                "  "
                f"{item.get('group_name')}/{item.get('rule_id')} "
                f"{item.get('condition')}={','.join(str(value) for value in item.get('values', []))} "
                f"reason={item.get('reason')}"
            )

    rule_sets = data.get("unevaluated_rule_sets", [])
    if isinstance(rule_sets, list) and rule_sets:
        print("Unevaluated rule sets:")
        for item in rule_sets:
            if not isinstance(item, dict):
                continue
            print(
                "  "
                f"{item.get('group_name')}/{item.get('rule_id')} "
                f"{item.get('kind')}={','.join(str(value) for value in item.get('values', []))} "
                f"state={item.get('state')}"
                f"{' behavior=' + str(item.get('failure_behavior')) if item.get('failure_behavior') else ''}"
                f"{' error=' + str(item.get('error')) if item.get('error') else ''}"
            )


def _format_rule_explain_input(input_traffic: object) -> str:
    if not isinstance(input_traffic, dict):
        return "-"
    parts = [
        f"{key}={value}"
        for key, value in input_traffic.items()
        if value is not None
    ]
    return ", ".join(parts) or "-"


def _parse_rule_conditions(items: list[str]) -> dict[str, list[str]]:
    conditions: dict[str, list[str]] = {}
    for item in items:
        key, sep, value = item.partition("=")
        key = key.strip()
        value = value.strip()
        if not sep or not key or not value:
            raise ParseError("rule condition must use KEY=VALUE")
        if key not in ALLOWED_RULE_CONDITIONS:
            supported = ", ".join(sorted(ALLOWED_RULE_CONDITIONS))
            raise ParseError(f"unsupported rule condition {key!r}; supported: {supported}")
        conditions.setdefault(key, []).append(value)
    return conditions


def _format_rule_conditions(conditions: dict[str, list[str]]) -> str:
    parts = []
    for key, values in sorted(conditions.items()):
        parts.append(f"{key}={','.join(values)}")
    return ";".join(parts) or "-"


def _rule_group_summary(group: RuleGroup) -> dict[str, object]:
    return {
        "name": group.name,
        "enabled": group.enabled,
        "priority": group.priority,
        "rule_count": len(group.rules),
        "rules": [rule.to_dict() for rule in group.rules],
    }


def _app_policy_status(args: argparse.Namespace) -> int:
    result = AppPolicyStore().load_or_disabled()
    data = _app_policy_status_data(result.policy, valid=result.valid, error=result.error)
    if args.json:
        _print_json(data)
        return 0
    if not result.valid:
        print("App policy: invalid")
        print(f"Error: {result.error}")
        print("Runtime behavior: fail closed")
        return 0
    _print_app_policy(data)
    return 0


def _app_policy_set_enabled(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    policy.enabled = bool(args.enabled)
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = _app_policy_mutation_data(policy, backup_path)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy {'enabled' if policy.enabled else 'disabled'}.")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_set_mode(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    policy.mode = AppPolicyMode(args.mode)
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = _app_policy_mutation_data(policy, backup_path)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy mode set to: {policy.mode.value}")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_set_default_action(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    policy.default_action = AppPolicyAction(args.default_action)
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = _app_policy_mutation_data(policy, backup_path)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy default action set to: {policy.default_action.value}")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_add(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    match: dict[str, list[str] | list[int]] = {}
    if args.process_name:
        match["process_name"] = [args.process_name]
    if args.process_path:
        match["process_path"] = [args.process_path]
    if args.process_path_regex:
        match["process_path_regex"] = [args.process_path_regex]
    if args.user:
        match["user"] = [args.user]
    if args.user_id is not None:
        match["user_id"] = [args.user_id]
    rule_id = args.id or _next_app_policy_rule_id(policy, match, args.action)
    if any(rule.id == rule_id for rule in policy.rules):
        raise ParseError(
            f"app policy rule already exists: {rule_id}; run `watchdog app-policy status` to inspect rules"
        )
    rule = AppPolicyRule(
        id=rule_id,
        action=args.action,
        match=match,
    )
    policy.rules.append(rule)
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = {
        "added": rule.to_dict(),
        "policy": _app_policy_status_data(policy),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("app-policy", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Added app policy rule: {rule.id}")
        print(f"Action: {_app_policy_action_value(rule.action)}")
        print(f"Confidence: {rule.match_confidence.value}")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_remove(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    original_count = len(policy.rules)
    policy.rules = [rule for rule in policy.rules if rule.id != args.rule_id]
    if len(policy.rules) == original_count:
        raise ParseError(
            f"app policy rule not found: {args.rule_id}; run `watchdog app-policy status` to inspect rules"
        )
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = {
        "removed": args.rule_id,
        "policy": _app_policy_status_data(policy),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("app-policy", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Removed app policy rule: {args.rule_id}")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_set_rule_enabled(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    if not any(rule.id == args.rule_id for rule in policy.rules):
        raise ParseError(
            f"app policy rule not found: {args.rule_id}; run `watchdog app-policy status` to inspect rules"
        )
    policy.rules = [
        AppPolicyRule(id=rule.id, action=rule.action, match=rule.match, enabled=bool(args.enabled))
        if rule.id == args.rule_id
        else rule
        for rule in policy.rules
    ]
    policy = AppPolicy.from_dict(policy.to_dict())
    backup_path = _create_section_backup("app-policy")
    store.save(policy)
    data = {
        "rule_id": args.rule_id,
        "enabled": bool(args.enabled),
        "policy": _app_policy_status_data(policy),
        "backup_path": str(backup_path),
        "rollback_point": _section_backup_rollback("app-policy", backup_path),
    }
    if args.json:
        _print_json(data)
    else:
        state = "enabled" if args.enabled else "disabled"
        print(f"App policy rule {state}: {args.rule_id}")
        print(f"Backup: {backup_path}")
    return 0


def _app_policy_status_data(
    policy: AppPolicy,
    *,
    valid: bool = True,
    error: str | None = None,
) -> dict[str, object]:
    return {
        "valid": valid,
        "error": error,
        "policy": policy.to_dict(),
        "rule_count": len(policy.rules),
        "enabled_rule_count": len([rule for rule in policy.rules if rule.enabled]),
        "rules": [
            {
                **rule.to_dict(),
                "match_confidence": rule.match_confidence.value,
            }
            for rule in policy.rules
        ],
    }


def _app_policy_mutation_data(policy: AppPolicy, backup_path: Path) -> dict[str, object]:
    data = _app_policy_status_data(policy)
    data["backup_path"] = str(backup_path)
    data["rollback_point"] = _section_backup_rollback("app-policy", backup_path)
    return data


def _create_section_backup(section: str) -> Path:
    return BackupManager().create_backup(
        reason="pre-policy-mutation",
        sections=[section],
    ).path


def _section_backup_rollback(section: str, backup_path: Path) -> dict[str, object]:
    return {
        "kind": "section-backup",
        "section": section,
        "path": str(backup_path),
    }


def _group_backup_rollback(section: str, backup_path: Path | None) -> dict[str, object] | None:
    if backup_path is None:
        return None
    return {
        "kind": "existing-group-backup",
        "section": section,
        "path": str(backup_path),
    }


def _app_policy_action_value(action: AppPolicyAction | str) -> str:
    return action.value if isinstance(action, AppPolicyAction) else action


def _print_app_policy(data: dict[str, object]) -> None:
    policy = data["policy"]
    if not isinstance(policy, dict):
        return
    print(f"App policy: {_on_off(bool(policy.get('enabled', False)))}")
    print(f"Mode: {policy.get('mode', '-')}")
    print(f"Default action: {policy.get('default_action', '-')}")
    print(f"Rules: {data['enabled_rule_count']}/{data['rule_count']} enabled")
    rules = data.get("rules", [])
    if not isinstance(rules, list) or not rules:
        return
    print("ID\tAction\tConfidence\tMatch")
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        print(
            "\t".join(
                [
                    str(rule.get("id", "-")),
                    str(rule.get("action", "-")),
                    str(rule.get("match_confidence", "-")),
                    _format_app_policy_match(rule.get("match", {})),
                ]
            )
        )


def _format_app_policy_match(match: object) -> str:
    if not isinstance(match, dict):
        return "-"
    parts = []
    for key, values in sorted(match.items()):
        if isinstance(values, list):
            parts.append(f"{key}={','.join(str(value) for value in values)}")
    return ";".join(parts) or "-"


def _next_app_policy_rule_id(
    policy: AppPolicy,
    match: dict[str, list[str]],
    action: str,
) -> str:
    matcher_key, matcher_values = next(iter(match.items()))
    base = _slug(f"{matcher_key}-{matcher_values[0]}-{action}")
    existing = {rule.id for rule in policy.rules}
    if base not in existing:
        return base
    index = 2
    while f"{base}-{index}" in existing:
        index += 1
    return f"{base}-{index}"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", value.strip().lower())
    slug = slug.strip("-_")
    return slug[:64] or "app-policy-rule"


def _dns_status(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    inventory = detect_resolver_manager(resolv_conf_path=Path(args.resolv_conf_path))
    data = _dns_status_data(policy, inventory.to_dict(), _dns_snapshot_path(args))
    if args.json:
        _print_json(data)
        return 0
    no_color = bool(getattr(args, "no_color", False))
    print(f"DNS mode: {_semantic(policy.mode.value, no_color=no_color)}")
    print(f"TUN hijack: {_on_off(policy.tun_hijack, no_color=no_color)}")
    print(f"Resolver manager: {data['resolver_manager']['manager']}")
    print(f"Nameservers: {', '.join(data['resolver_manager']['nameservers']) or '-'}")
    print(f"Channels: {data['channels']['configured']}/{data['channels']['total']}")
    print(f"Static IP: {_on_off(policy.static_ip_enabled, no_color=no_color)} ({len(policy.static_ips)} entries)")
    print(f"Rules: {_on_off(policy.rules_enabled, no_color=no_color)} ({len(policy.rules)} rules)")
    fakeip_active = data["features"]["proxy_resolution_channel_active"]
    fakeip_suffix = ""
    if not fakeip_active:
        fakeip_suffix = f" - {_fakeip_inactive_reason(policy)}"
    print(
        f"FakeIP: {_on_off(bool(fakeip_active), no_color=no_color)} "
        f"({policy.fakeip_inet4_range}, {policy.fakeip_inet6_range})"
        + fakeip_suffix
    )
    print(f"ECS direct: {_on_off(policy.ecs_direct_enabled, no_color=no_color)}")
    print(f"Snapshot: {data['snapshot']['path']} ({_semantic(data['snapshot']['status'], no_color=no_color)})")
    return 0


def _dns_test(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    domain = args.domain or policy.test_domain
    tester = DNSTester(timeout=args.timeout)
    if args.auto or not policy.channels:
        recommendation = tester.recommend_auto_setup(test_domain=domain)
        data: dict[str, object] = {
            "mode": "auto",
            "test_domain": domain,
            "recommendation": recommendation.to_dict(),
        }
    else:
        channel_results = {
            name.value: tester.test_channel(channel, domain).to_dict()
            for name, channel in sorted(policy.channels.items(), key=lambda item: item[0].value)
        }
        data = {
            "mode": policy.mode.value,
            "test_domain": domain,
            "channel_results": channel_results,
        }
    if args.json:
        _print_json(data)
        return 0
    print(f"DNS test domain: {domain}")
    for channel, result in _dns_channel_results(data).items():
        ok_count = sum(1 for item in result["results"] if item["ok"])
        total = len(result["results"])
        print(f"{channel}: {ok_count}/{total} resolver(s) passed")
    return 0


def _dns_diagnose(args: argparse.Namespace) -> int:
    traffic = TrafficInfo(
        domain=args.domain,
        ip=args.ip,
        port=args.port,
        protocol=args.protocol,
        network=args.network,
        process_name=args.process_name,
        process_path=args.process_path,
    )
    trust_path = Path(args.ruleset_trust_file) if args.ruleset_trust_file else None
    trust_registry = RuleSetTrustStore(trust_path).load()
    rule_groups = RuleStore().list_groups()
    routing_state = StateManager().load()
    app_policy = AppPolicyStore().load_or_disabled().policy
    dns_policy = _load_dns_policy(args)
    diagnostic = diagnose_route_dns(
        traffic=traffic,
        rule_groups=rule_groups,
        dns_policy=dns_policy,
        app_policy=app_policy,
        routing_state=routing_state,
        trust_registry=trust_registry,
    )
    chain_diagnostic = _chain_diagnostic_for_action(
        diagnostic.route_action,
        dns_policy=dns_policy,
    )
    if chain_diagnostic is not None:
        diagnostic = diagnose_route_dns(
            traffic=traffic,
            rule_groups=rule_groups,
            dns_policy=dns_policy,
            app_policy=app_policy,
            routing_state=routing_state,
            trust_registry=trust_registry,
            chain_diagnostic=chain_diagnostic,
        )
    if args.json:
        _print_json(diagnostic.to_dict())
    else:
        _print_route_dns_diagnostic(diagnostic)
    return 0


def _dns_apply(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    snapshot_path = _dns_snapshot_path(args)
    entrypoint = LocalDNSEntryPoint(
        address=args.entrypoint_address,
        port=int(args.entrypoint_port),
        systemd_link=args.systemd_link,
    )
    inventory = detect_resolver_manager(resolv_conf_path=Path(args.resolv_conf_path))
    plan = {
        "policy_mode": policy.mode.value,
        "tun_hijack": policy.tun_hijack,
        "resolver_manager": inventory.to_dict(),
        "entrypoint": {
            "address": entrypoint.address,
            "port": entrypoint.port,
            "systemd_link": entrypoint.systemd_link,
        },
        "snapshot_path": str(snapshot_path),
        "rollback_snapshot": {
            "path": str(snapshot_path),
            "status": "present" if snapshot_path.exists() else "missing",
            "will_create": False,
        },
        "would_apply": policy.mode != DNSMode.OFF and policy.tun_hijack,
        "rollback_plan": "restore saved DNS state from snapshot",
        "confirmation_required": True,
    }
    if args.dry_run:
        return _dns_apply_output(args, {**plan, "status": "dry-run"})
    if not args.yes:
        raise ParseError("dns apply requires --yes or --dry-run")
    if entrypoint.port != 53:
        raise ParseError(
            "dns apply requires --entrypoint-port 53; system resolvers are configured by address only"
        )
    if plan["would_apply"] and not args.skip_entrypoint_check:
        _require_dns_entrypoint(entrypoint, timeout=float(args.entrypoint_timeout))

    manager = SystemDNSStateManager(resolv_conf_path=Path(args.resolv_conf_path))
    snapshot_for_apply = None
    snapshot_preexisting = False
    if plan["would_apply"]:
        existing_snapshot = load_snapshot(snapshot_path)
        if existing_snapshot is None:
            snapshot_for_apply = manager.save_state(systemd_link=args.systemd_link)
            _save_dns_snapshot(snapshot_path, snapshot_for_apply)
            plan["rollback_snapshot"]["will_create"] = True
        else:
            snapshot_preexisting = True
    controller = DNSHijackController(manager, entrypoint=entrypoint)
    result = controller.apply(
        policy,
        snapshot=snapshot_for_apply,
        systemd_link=args.systemd_link,
    )
    data = {
        **plan,
        "status": "applied" if result.applied else "skipped",
        "reason": result.reason,
        "snapshot_saved": snapshot_preexisting or snapshot_for_apply is not None,
        "rollback_snapshot": {
            **plan["rollback_snapshot"],
            "status": "present" if snapshot_preexisting or snapshot_for_apply is not None else "missing",
            "preexisting": snapshot_preexisting,
        },
    }
    return _dns_apply_output(args, data)


def _dns_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ParseError("dns reset requires --yes")
    snapshot_path = _dns_snapshot_path(args)
    snapshot = load_snapshot(snapshot_path)
    if snapshot is None:
        data = {
            "status": "nothing-to-restore",
            "snapshot_path": str(snapshot_path),
            "rollback_snapshot": {
                "path": str(snapshot_path),
                "status": "not-found",
                "restored": False,
            },
        }
        if args.json:
            _print_json(data)
        else:
            print("No DNS snapshot found; nothing to restore.")
            print(f"Snapshot: {snapshot_path}")
        return 0
    manager = SystemDNSStateManager(resolv_conf_path=Path(args.resolv_conf_path))
    manager.restore_state(snapshot)
    try:
        snapshot_path.unlink()
    except FileNotFoundError:
        pass
    data = {
        "status": "restored",
        "snapshot_path": str(snapshot_path),
        "rollback_snapshot": {
            "path": str(snapshot_path),
            "status": "removed-after-restore",
            "restored": True,
        },
        "resolver_manager": snapshot.inventory.manager.value,
        "confirmation_required": True,
    }
    if args.json:
        _print_json(data)
    else:
        print("DNS state restored.")
        print(f"Snapshot: {snapshot_path}")
    return 0


def _dns_policy_store(args: argparse.Namespace) -> DNSPolicyStore:
    path = Path(args.policy_file) if getattr(args, "policy_file", None) else None
    return DNSPolicyStore(path)


def _dns_policy_mutation_data(
    policy: DNSPolicy,
    backup_path: Path,
    rollback_point: dict[str, object],
) -> dict[str, object]:
    return {
        "policy": policy.to_dict(),
        "backup_path": str(backup_path),
        "rollback_point": rollback_point,
    }


def _create_dns_policy_backup(
    store: DNSPolicyStore,
) -> tuple[Path, dict[str, object]]:
    if store.path.name == "dns-policy.json":
        backup_path = BackupManager(config_dir=store.path.parent).create_backup(
            reason="pre-policy-mutation",
            sections=["dns-policy"],
        ).path
        return backup_path, _section_backup_rollback("dns-policy", backup_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = (
        store.path.parent
        / "backups"
        / f"{store.path.stem}-pre-policy-mutation-{stamp}{store.path.suffix or '.json'}"
    )
    payload = store.path.read_bytes() if store.path.exists() else b"{}\n"
    atomic_write_bytes(backup_path, payload)
    return backup_path, {
        "kind": "file-backup",
        "path": str(backup_path),
        "target": str(store.path),
    }


def _save_dns_policy_mutation(
    store: DNSPolicyStore,
    policy: DNSPolicy,
) -> dict[str, object]:
    backup_path, rollback_point = _create_dns_policy_backup(store)
    store.save(policy)
    return _dns_policy_mutation_data(policy, backup_path, rollback_point)


def _dns_channel_add(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    name = DNSChannelName(args.name)
    if name in policy.channels:
        raise ParseError(
            f"dns channel already exists: {name.value}; run `watchdog dns status --json` to inspect channels"
        )
    policy.channels[name] = DNSChannel(name=name)
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Added DNS channel: {name.value}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_channel_remove(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    name = DNSChannelName(args.name)
    if name not in policy.channels:
        raise ParseError(
            f"dns channel not found: {name.value}; run `watchdog dns status --json` to inspect channels"
        )
    referencing_rules = [rule.id for rule in policy.rules if rule.channel == name]
    if referencing_rules:
        raise ParseError(
            f"dns channel {name.value} is referenced by rule(s): "
            f"{', '.join(sorted(referencing_rules))}; remove those rules first"
        )
    del policy.channels[name]
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Removed DNS channel: {name.value}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_resolver_add(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    name = DNSChannelName(args.channel)
    channel = policy.channels.setdefault(
        name,
        DNSChannel(name=name, strategy=args.strategy),
    )
    if any(resolver.uri == args.uri for resolver in channel.resolvers):
        raise ParseError(f"resolver already exists in channel {name.value}: {args.uri}")
    channel.resolvers.append(
        Resolver(uri=args.uri, label=args.label, enabled=not args.disabled)
    )
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Added resolver to channel {name.value}: {args.uri}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_resolver_remove(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    name = DNSChannelName(args.channel)
    channel = policy.channels.get(name)
    if channel is None or not any(resolver.uri == args.uri for resolver in channel.resolvers):
        raise ParseError(f"resolver not found in channel {name.value}: {args.uri}")
    channel.resolvers = [resolver for resolver in channel.resolvers if resolver.uri != args.uri]
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Removed resolver from channel {name.value}: {args.uri}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_resolver_set_enabled(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    name = DNSChannelName(args.channel)
    channel = policy.channels.get(name)
    if channel is None or not any(resolver.uri == args.uri for resolver in channel.resolvers):
        raise ParseError(f"resolver not found in channel {name.value}: {args.uri}")
    channel.resolvers = [
        Resolver(uri=resolver.uri, label=resolver.label, enabled=bool(args.enabled), metadata=resolver.metadata)
        if resolver.uri == args.uri
        else resolver
        for resolver in channel.resolvers
    ]
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        state = "enabled" if args.enabled else "disabled"
        print(f"Resolver {state} in channel {name.value}: {args.uri}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_rule_add(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    if any(rule.id == args.id for rule in policy.rules):
        raise ParseError(
            f"dns rule already exists: {args.id}; run `watchdog dns status --json` to inspect rules"
        )
    rule = DNSRule(
        id=args.id,
        pattern=args.pattern,
        action=DNSRuleAction(args.action),
        channel=DNSChannelName(args.channel) if args.channel else None,
        enabled=not args.disabled,
        priority=args.priority,
    )
    if rule.action == DNSRuleAction.REJECT and args.channel is not None:
        raise ParseError("--channel is incompatible with --action reject")
    if rule.channel is not None and rule.channel not in policy.channels:
        raise ParseError(
            f"dns channel not found: {rule.channel.value}; "
            "create it before adding a rule that uses it"
        )
    policy.rules.append(rule)
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Added DNS rule: {rule.id}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_rule_remove(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    original_count = len(policy.rules)
    policy.rules = [rule for rule in policy.rules if rule.id != args.id]
    if len(policy.rules) == original_count:
        raise ParseError(
            f"dns rule not found: {args.id}; run `watchdog dns status --json` to inspect rules"
        )
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Removed DNS rule: {args.id}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_rule_set_enabled(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    if not any(rule.id == args.id for rule in policy.rules):
        raise ParseError(
            f"dns rule not found: {args.id}; run `watchdog dns status --json` to inspect rules"
        )
    policy.rules = [
        DNSRule(
            id=rule.id,
            pattern=rule.pattern,
            action=rule.action,
            channel=rule.channel,
            enabled=bool(args.enabled),
            priority=rule.priority,
        )
        if rule.id == args.id
        else rule
        for rule in policy.rules
    ]
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        state = "enabled" if args.enabled else "disabled"
        print(f"DNS rule {state}: {args.id}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_static_ip_add(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    new_entry = StaticIPEntry(
        domain=args.domain,
        ip=args.ip,
        enabled=not args.disabled,
    )
    if any(
        entry.domain == new_entry.domain and entry.ip == new_entry.ip
        for entry in policy.static_ips
    ):
        raise ParseError(
            f"static IP mapping already exists: {new_entry.domain} -> {new_entry.ip}"
        )
    policy.static_ips.append(new_entry)
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Added static IP mapping: {args.domain} -> {args.ip}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _dns_static_ip_remove(args: argparse.Namespace) -> int:
    store = _dns_policy_store(args)
    policy = store.load()
    domain = args.domain.strip().lower().rstrip(".")
    target_ip = args.ip.strip() if args.ip else None
    original_count = len(policy.static_ips)
    if target_ip:
        policy.static_ips = [
            entry
            for entry in policy.static_ips
            if not (entry.domain == domain and entry.ip == target_ip)
        ]
    else:
        policy.static_ips = [entry for entry in policy.static_ips if entry.domain != domain]
    if len(policy.static_ips) == original_count:
        raise ParseError(f"static IP mapping not found for domain: {args.domain}")
    policy = DNSPolicy.from_dict(policy.to_dict())
    data = _save_dns_policy_mutation(store, policy)
    if args.json:
        _print_json(data)
    else:
        print(f"Removed static IP mapping(s) for domain: {args.domain}")
        print(f"Backup: {data['backup_path']}")
    return 0


def _add_dns_common_paths(
    parser: argparse.ArgumentParser,
    include_resolv_conf: bool = True,
    include_snapshot: bool = True,
) -> None:
    parser.add_argument("--policy-file", help="DNS policy JSON file")
    if include_snapshot:
        parser.add_argument("--snapshot-file", help="DNS state snapshot JSON file")
    if include_resolv_conf:
        parser.add_argument("--resolv-conf-path", default="/etc/resolv.conf", help="resolv.conf path")


def _load_dns_policy(args: argparse.Namespace) -> DNSPolicy:
    path = Path(args.policy_file) if getattr(args, "policy_file", None) else None
    return DNSPolicyStore(path).load()


def _dns_snapshot_path(args: argparse.Namespace) -> Path:
    if getattr(args, "snapshot_file", None):
        return Path(args.snapshot_file)
    return Path(
        os.environ.get(
            "WATCHDOGVPN_DNS_SNAPSHOT_FILE",
            resolve_config_dir() / DEFAULT_DNS_SNAPSHOT_NAME,
        )
    )


def _dns_status_data(
    policy: DNSPolicy,
    resolver_manager: dict[str, object],
    snapshot_path: Path,
) -> dict[str, object]:
    return {
        "policy": policy.to_dict(),
        "resolver_manager": resolver_manager,
        "channels": {
            "configured": len(policy.channels),
            "total": len(DNSChannelName),
            "names": sorted(name.value for name in policy.channels),
        },
        "features": {
            "tun_hijack": policy.tun_hijack,
            "resolve_inbound_domains": policy.resolve_inbound_domains,
            "static_ip_enabled": policy.static_ip_enabled,
            "rules_enabled": policy.rules_enabled,
            "ecs_direct_enabled": policy.ecs_direct_enabled,
            "proxy_resolution_channel": policy.proxy_resolution_channel,
            "proxy_resolution_channel_active": fakeip_policy_ready(policy),
        },
        "snapshot": {
            "path": str(snapshot_path),
            "status": "present" if snapshot_path.exists() else "missing",
        },
    }


def _fakeip_inactive_reason(policy: DNSPolicy) -> str:
    if policy.mode == DNSMode.OFF:
        return "DNS mode is off"
    if policy.proxy_resolution_channel != "fakeip":
        return f"proxy resolution uses {policy.proxy_resolution_channel}"
    proxy_channel = policy.channels.get(DNSChannelName.PROXY)
    if proxy_channel is None:
        return "requires a configured proxy DNS channel"
    return "requires an enabled resolver in the proxy DNS channel"


def _dns_channel_results(data: dict[str, object]) -> dict[str, dict]:
    if "channel_results" in data:
        return dict(data["channel_results"])
    recommendation = data.get("recommendation", {})
    if not isinstance(recommendation, dict):
        return {}
    return dict(recommendation.get("channel_results", {}))


def _dns_apply_output(args: argparse.Namespace, data: dict[str, object]) -> int:
    if args.json:
        _print_json(data)
    else:
        print(f"DNS apply status: {data['status']}")
        print(f"Policy mode: {data['policy_mode']}")
        print(f"Would apply: {_on_off(bool(data['would_apply']))}")
        print(f"Entrypoint: {data['entrypoint']['address']}:{data['entrypoint']['port']}")
        print(f"Snapshot: {data['snapshot_path']}")
        if data.get("reason"):
            print(f"Reason: {data['reason']}")
    return 0


def _print_route_dns_diagnostic(diagnostic: RouteDNSDiagnostic) -> None:
    print("Route/DNS diagnostic: configured policy only, not live traffic observation")
    print(f"Confidence: {diagnostic.confidence.value}")
    print(f"Route action: {diagnostic.route_action or 'unknown'}")
    if diagnostic.route_source:
        source = diagnostic.route_source.get("source") or "-"
        rule_id = diagnostic.route_source.get("rule_id") or "-"
        group_name = diagnostic.route_source.get("group_name") or "-"
        print(f"Route source: {source} group={group_name} rule={rule_id}")
    print(f"DNS channel: {diagnostic.dns_channel or '-'}")
    print(f"DNS path: {diagnostic.dns_path}")
    print(f"Reason: {diagnostic.dns_reason}")
    if diagnostic.chain_diagnostic is not None:
        print("Chain diagnostic:")
        for line in diagnostic.chain_diagnostic.to_human_lines():
            print(f"  {line}")


def _chain_diagnostic_for_action(
    route_action: str | None,
    *,
    dns_policy: DNSPolicy,
) -> ChainRouteDiagnostic | None:
    if route_action is None or chain_target(route_action) is None:
        return None
    return diagnose_chain_route_action(
        route_action,
        chain_document=RouteChainStore().load(),
        dns_policy=dns_policy,
        resolver=ChainRuntimeResolver(),
        config=AppConfig().load(),
    )


def _require_dns_entrypoint(entrypoint: LocalDNSEntryPoint, timeout: float) -> None:
    try:
        with socket.create_connection((entrypoint.address, entrypoint.port), timeout=timeout):
            return
    except OSError as exc:
        raise DNSStateError(
            "local DNS entrypoint is not reachable; start the DNS runtime first "
            "or use --dry-run"
        ) from exc


def _save_dns_snapshot(path: Path, snapshot: DNSStateSnapshot) -> None:
    save_snapshot(path, snapshot)


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _print_node_group_auto_test(data: dict) -> None:
    print(f"Node group: {data.get('group_name')}")
    print(f"Result: {data.get('result')}")
    print(f"Selected profile: {data.get('selected_profile_id') or '-'}")
    tested = data.get("tested") or []
    if tested:
        print("Tested:")
        for item in tested:
            latency = item.get("latency_ms")
            latency_label = "-" if latency is None else f"{latency} ms"
            connected = _on_off(bool(item.get("connected")))
            print(
                f"  {item.get('profile_id')}\tconnected={connected}\t"
                f"health={item.get('health_status')}\tlatency={latency_label}"
            )
    candidates = data.get("candidates") or []
    if candidates:
        print("Ranking:")
        for item in candidates:
            latency = item.get("latency_score")
            latency_label = "-" if latency is None else f"{latency} ms"
            print(
                f"  {item.get('profile_id')}\ttotal={item.get('total')}\t"
                f"resilience={item.get('resilience_score')}\tlatency={latency_label}"
            )


def _require_profile(store: ProfileStore, profile_id: str) -> Profile:
    profile = store.get(profile_id)
    if profile is None:
        raise ParseError(
            f"profile not found: {profile_id}; run `watchdog profile list` to inspect saved profiles"
        )
    return profile


def _require_provider(store: ProviderStore, provider_id: str) -> Provider:
    provider = store.get(provider_id)
    if provider is None:
        raise ProviderNotFoundError(
            f"provider not found: {provider_id}; run `watchdog provider list` to inspect saved providers"
        )
    return provider


def _require_node_group(store: NodeGroupStore, name: str) -> NodeGroup:
    group = store.get(name)
    if group is None:
        raise ParseError(f"node group not found: {name}")
    return group


def _node_group_summary(group: NodeGroup) -> dict:
    return group.to_dict()


def _print_profile_list(profiles: list[Profile], *, wide: bool, pool_only: bool, no_color: bool = False) -> None:
    providers = {provider.id: provider for provider in ProviderStore().list()}
    summary = _profile_list_summary(profiles)
    scope = "rotation pool" if pool_only else "all saved profiles"
    print(color.style(f"Profiles ({scope})", "bold", no_color=no_color))
    print(
        "Total: {total} | Manual: {manual} | Provider-owned: {provider_owned} | "
        "Enabled: {enabled} | Rotation: {rotation}".format(**summary)
    )
    print(
        "Health: ok={ok} unknown={unknown} down={down} degraded={degraded}".format(
            **summary["health"]
        )
    )
    duplicate_groups = _duplicate_profile_candidate_count(profiles)
    if duplicate_groups:
        print(
            f"{color.warning_label(no_color=no_color)}: duplicate profile candidates detected: {duplicate_groups} group(s); "
            "no data changed."
        )
    print()

    manual_profiles = [
        profile for profile in profiles if profile.source == ProfileSource.MANUAL
    ]
    if manual_profiles:
        _print_profile_group(
            "Manual profiles",
            manual_profiles,
            wide=wide,
            no_color=no_color,
        )

    provider_profiles: dict[str, list[Profile]] = {}
    for profile in profiles:
        if profile.source != ProfileSource.SUBSCRIPTION:
            continue
        provider_profiles.setdefault(profile.provider_id or "-", []).append(profile)

    for provider_id in sorted(provider_profiles):
        provider = providers.get(provider_id)
        if provider is None:
            title = f"Provider: {provider_id}"
        elif provider.name == provider.id:
            title = f"Provider: {provider.id}"
        else:
            title = f"Provider: {provider.name} ({provider.id})"
        _print_profile_group(title, provider_profiles[provider_id], wide=wide, no_color=no_color)


def _profile_list_summary(profiles: list[Profile]) -> dict[str, object]:
    health = {"ok": 0, "unknown": 0, "down": 0, "degraded": 0}
    for profile in profiles:
        status = profile.health_status if profile.health_status in health else "unknown"
        health[status] += 1
    return {
        "total": len(profiles),
        "manual": len([profile for profile in profiles if profile.source == ProfileSource.MANUAL]),
        "provider_owned": len(
            [profile for profile in profiles if profile.source == ProfileSource.SUBSCRIPTION]
        ),
        "enabled": len([profile for profile in profiles if profile.enabled]),
        "rotation": len([profile for profile in profiles if profile.in_rotation_pool]),
        "health": health,
    }


def _duplicate_profile_candidate_count(profiles: list[Profile]) -> int:
    by_fingerprint: dict[str, int] = {}
    for profile in profiles:
        fingerprint = profile_fingerprint(profile)
        by_fingerprint[fingerprint] = by_fingerprint.get(fingerprint, 0) + 1
    return len([count for count in by_fingerprint.values() if count > 1])


def _print_profile_group(title: str, profiles: list[Profile], *, wide: bool, no_color: bool = False) -> None:
    print(color.style(title, "bold", no_color=no_color))
    rows = [_profile_row(profile, wide=wide) for profile in _sorted_profiles(profiles)]
    columns = ("Name", "Protocol", "Category", "Health", "Enabled", "Rotation", "ID")
    widths = [
        max(len(str(row[index])) for row in [columns, *rows])
        for index in range(len(columns))
    ]
    print(_format_profile_row(columns, widths))
    print(_format_profile_row(tuple("-" * width for width in widths), widths))
    for row in rows:
        print(_format_profile_row(row, widths, semantic_columns={3, 4, 5}, no_color=no_color))
    print()


def _profile_row(profile: Profile, *, wide: bool) -> tuple[str, str, str, str, str, str, str]:
    return (
        profile.name,
        profile.protocol.value,
        profile_resilience_category(profile).value,
        _profile_health_label(profile.health_status),
        _on_off_plain(profile.enabled),
        _on_off_plain(profile.in_rotation_pool),
        profile.id if wide else _truncate_profile_id(profile.id),
    )


def _sorted_profiles(profiles: list[Profile]) -> list[Profile]:
    return sorted(
        profiles,
        key=lambda profile: (
            not profile.enabled,
            not profile.in_rotation_pool,
            profile.health_status != "ok",
            profile.name.lower(),
            profile.id,
        ),
    )


def _profile_health_label(status: str) -> str:
    if status == "ok":
        return "OK"
    if status == "down":
        return "DOWN"
    if status == "degraded":
        return "DEGRADED"
    return "UNKNOWN"


def _truncate_profile_id(profile_id: str, limit: int = 32) -> str:
    if len(profile_id) <= limit:
        return profile_id
    return f"{profile_id[: limit - 1]}..."


def _format_profile_row(
    row: tuple[str, ...],
    widths: list[int],
    *,
    semantic_columns: set[int] | None = None,
    no_color: bool = False,
) -> str:
    semantic_columns = semantic_columns or set()
    parts = []
    for index, (value, width) in enumerate(zip(row, widths)):
        text = str(value)
        if index in semantic_columns:
            parts.append(_semantic(text, no_color=no_color) + (" " * max(width - len(text), 0)))
        else:
            parts.append(text.ljust(width))
    return "  ".join(parts)


def _profile_summary(profile: Profile) -> dict[str, object]:
    return {
        "id": profile.id,
        "name": profile.name,
        "protocol": profile.protocol.value,
        "resilience_category": profile_resilience_category(profile).value,
        "source": profile.source.value,
        "provider_id": profile.provider_id,
        "in_rotation_pool": profile.in_rotation_pool,
        "enabled": profile.enabled,
        "health_status": profile.health_status,
        "latency_ms": profile.latency_ms,
        "last_health_check": profile.last_health_check.isoformat() if profile.last_health_check else None,
        "last_latency_check": profile.last_latency_check.isoformat() if profile.last_latency_check else None,
        "config_included": False,
    }


def _provider_summary(provider: Provider) -> dict:
    metadata = provider.metadata or {}
    return {
        "id": provider.id,
        "name": provider.name,
        "url": _redact_url(provider.url),
        "rotation_enabled": provider.rotation_enabled,
        "node_count": len(provider.profiles),
        "last_updated": provider.last_updated.isoformat() if provider.last_updated else None,
        "traffic": _traffic_label(metadata),
        "expires_at": metadata.get("expires_at") or metadata.get("expire") or metadata.get("expires"),
        "metadata_included": False,
    }


def _traffic_label(metadata: dict) -> str:
    used = metadata.get("traffic_used") or metadata.get("used")
    total = metadata.get("traffic_limit") or metadata.get("total")
    if used is not None and total is not None:
        return f"{used}/{total}"
    if used is not None:
        return str(used)
    return ""


def _read_text_input() -> str:
    if not sys.stdin.isatty():
        content = sys.stdin.read()
        if content.strip():
            return content
    editor = os.environ.get("EDITOR")
    if not editor:
        raise ParseError("profile add --text requires stdin content or EDITOR")
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as temp:
        subprocess.run([editor, temp.name], check=False)
        temp.seek(0)
        content = temp.read()
    if not content.strip():
        raise ParseError("profile text input is empty")
    return content


def _prompt_required(label: str) -> str:
    if not sys.stdin.isatty():
        raise ParseError(f"{label} is required")
    value = input(f"{label}: ").strip()
    if not value:
        raise ParseError(f"{label} is required")
    return value


def _prompt_optional(label: str) -> str:
    if not sys.stdin.isatty():
        return ""
    return input(f"{label}: ").strip()


def _prompt_rotation_pool(profile: Profile) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"Add profile '{profile.name}' to the rotation pool? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _on_off_plain(value: bool) -> str:
    return "on" if value else "off"


def _on_off(value: bool, *, no_color: bool = False) -> str:
    return _semantic(_on_off_plain(value), no_color=no_color)


def _danger_on_off(value: bool, *, no_color: bool = False) -> str:
    text = _on_off_plain(value)
    if not value:
        return text
    return color.style(text, "red", no_color=no_color)


def _semantic(value: object, *, no_color: bool = False) -> str:
    return color.semantic(value, no_color=no_color)


def _redact_url(url: str) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/<redacted>"


def _error(message: str, *, as_json: bool = False) -> None:
    if as_json:
        # One JSON envelope, one channel, whether the command succeeds or
        # fails (WDCLI-009): stdout, matching the shape connection commands
        # already use (daemon/protocol.py::Response.to_dict()), so a
        # consumer never has to guess which stream or schema an error will
        # arrive on. Human-readable diagnostics stay on stderr, unchanged.
        _print_json({"version": 1, "type": "response", "ok": False, "payload": {}, "error": message})
    else:
        print(f"error: {message}", file=sys.stderr)


def _exit() -> NoReturn:
    raise SystemExit(main())


if __name__ == "__main__":
    _exit()
