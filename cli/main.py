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
from cli.ipc.client import WatchdogIPCClient
from cli.ipc.errors import WatchdogIPCError
from config.app_config import AppConfig
from config.backup_manager import BackupManager
from config.dns_policy_store import DNSPolicyStore
from config.lan_sharing import (
    lan_sharing_credentials_path,
    load_or_create_lan_sharing_credentials,
)
from config.paths import resolve_config_dir
from config.persistence import PersistentStoreError, dump_json
from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
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
from dns.models import DNSChannelName, DNSMode, DNSPolicy
from dns.resolver_inventory import detect_resolver_manager
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
from diagnostics.routing import RouteDiagnostic, diagnose_route
from metrics.models import MetricsDocument, MetricsRedactionMode
from metrics.store import MetricsStore
from models.profile import Profile
from models.provider import Provider
from node_groups.models import NodeGroup, NodeGroupSelectionMode
from node_groups.store import NodeGroupStore, NodeGroupStoreError
from parsers import ParseError
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
from rules.ruleset_trust_store import RuleSetTrustStore


DEFAULT_DNS_SNAPSHOT_NAME = "dns-state.json"
CONFIG_SET_KEYS = frozenset(
    {
        "watchdog.check_interval_seconds",
        "rotation.scheduled_interval_hours",
        "rotation.test_url",
        "rotation.test_timeout_seconds",
        "rotation.latency_max_stale_seconds",
        "lan_sharing.enabled",
        "lan_sharing.mode",
        "lan_sharing.bind_address",
        "lan_sharing.socks_port",
        "lan_sharing.http_port",
        "lan_sharing.authentication_required",
        "lan_sharing.firewall_managed",
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
        "lan_sharing.enabled",
        "lan_sharing.authentication_required",
        "lan_sharing.firewall_managed",
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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    try:
        return int(args.handler(args))
    except (ProviderLimitError, ProviderNotFoundError) as exc:
        _error(str(exc))
        return 65
    except RuleStoreError as exc:
        _error(str(exc))
        return 65
    except RuleSetLifecycleError as exc:
        _error(str(exc))
        return 65
    except NodeGroupStoreError as exc:
        _error(str(exc))
        return 65
    except ParseError as exc:
        _error(str(exc))
        return 65
    except FileNotFoundError as exc:
        _error(str(exc))
        return 66
    except PersistentStoreError as exc:
        _error(str(exc))
        return 70
    except WatchdogIPCError as exc:
        _error(str(exc))
        return exc.exit_code
    except (DNSHijackError, DNSStateError, OSError, ValueError) as exc:
        _error(str(exc))
        return 70


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchdog", description="WatchdogVPN command line")
    subparsers = parser.add_subparsers(dest="command")

    connect_parser = subparsers.add_parser("connect", help="Connect through the WatchdogVPN daemon")
    connect_parser.add_argument("profile_id", help="Profile ID to connect")
    connect_parser.add_argument("--json", action="store_true", help="Print JSON")
    connect_parser.set_defaults(handler=_connection_connect)

    disconnect_parser = subparsers.add_parser("disconnect", help="Disconnect through the WatchdogVPN daemon")
    disconnect_parser.add_argument("--json", action="store_true", help="Print JSON")
    disconnect_parser.set_defaults(handler=_connection_disconnect)

    status_parser = subparsers.add_parser("status", help="Show daemon connection status")
    status_parser.add_argument("--json", action="store_true", help="Print JSON")
    status_parser.set_defaults(handler=_connection_status)

    rotate_parser = subparsers.add_parser("rotate", help="Rotate connection through the WatchdogVPN daemon")
    rotate_parser.add_argument("--force", action="store_true", help="Force rotation even if conservative checks apply")
    rotate_parser.add_argument("--json", action="store_true", help="Print JSON")
    rotate_parser.set_defaults(handler=_connection_rotate)

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

    profile_parser = subparsers.add_parser("profile", help="Manage local profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")

    add_parser = profile_subparsers.add_parser("add", help="Add a manual profile")
    add_source = add_parser.add_mutually_exclusive_group(required=True)
    add_source.add_argument("--clipboard", action="store_true", help="Read profile content from clipboard")
    add_source.add_argument("--uri", help="Import one profile URI")
    add_source.add_argument("--file", help="Import profile content from file")
    add_source.add_argument("--text", action="store_true", help="Read profile content from stdin or editor")
    add_parser.set_defaults(handler=_profile_add)

    list_parser = profile_subparsers.add_parser("list", help="List saved profiles")
    list_parser.add_argument("--json", action="store_true", help="Print JSON")
    list_parser.add_argument("--pool", action="store_true", help="Show rotation pool only")
    list_parser.set_defaults(handler=_profile_list)

    remove_parser = profile_subparsers.add_parser("remove", help="Remove a saved profile")
    remove_parser.add_argument("profile_id")
    remove_parser.set_defaults(handler=_profile_remove)

    enable_parser = profile_subparsers.add_parser("enable", help="Enable a saved profile")
    enable_parser.add_argument("profile_id")
    enable_parser.set_defaults(handler=_profile_set_enabled)
    enable_parser.set_defaults(enabled=True)

    disable_parser = profile_subparsers.add_parser("disable", help="Disable a saved profile")
    disable_parser.add_argument("profile_id")
    disable_parser.set_defaults(handler=_profile_set_enabled)
    disable_parser.set_defaults(enabled=False)

    rotation_parser = profile_subparsers.add_parser("rotation", help="Change profile rotation-pool membership")
    rotation_parser.add_argument("profile_id")
    rotation_group = rotation_parser.add_mutually_exclusive_group(required=True)
    rotation_group.add_argument("--enable", action="store_true", help="Add profile to rotation pool")
    rotation_group.add_argument("--disable", action="store_true", help="Remove profile from rotation pool")
    rotation_parser.set_defaults(handler=_profile_rotation)

    provider_parser = subparsers.add_parser("provider", help="Manage external providers")
    provider_subparsers = provider_parser.add_subparsers(dest="provider_command")

    provider_add_parser = provider_subparsers.add_parser("add", help="Add an external provider")
    provider_add_parser.add_argument("url", nargs="?", help="External provider subscription URL")
    provider_add_parser.add_argument("--name", help="Free-form provider label")
    provider_add_parser.set_defaults(handler=_provider_add)

    provider_list_parser = provider_subparsers.add_parser("list", help="List external providers")
    provider_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_list_parser.set_defaults(handler=_provider_list)

    provider_stats_parser = provider_subparsers.add_parser("stats", help="Show provider statistics")
    provider_stats_parser.add_argument("provider_id")
    provider_stats_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_stats_parser.set_defaults(handler=_provider_stats)

    provider_update_parser = provider_subparsers.add_parser("update", help="Update provider nodes")
    provider_update_target = provider_update_parser.add_mutually_exclusive_group(required=True)
    provider_update_target.add_argument("provider_id", nargs="?", help="Provider ID")
    provider_update_target.add_argument("--all", action="store_true", help="Update all providers")
    provider_update_parser.set_defaults(handler=_provider_update)

    provider_remove_parser = provider_subparsers.add_parser("remove", help="Remove provider and owned nodes")
    provider_remove_parser.add_argument("provider_id")
    provider_remove_parser.set_defaults(handler=_provider_remove)

    provider_edit_parser = provider_subparsers.add_parser("edit", help="Edit provider metadata")
    provider_edit_parser.add_argument("provider_id")
    provider_edit_parser.add_argument("--name", help="New free-form provider label")
    provider_edit_parser.add_argument("--url", help="New subscription URL")
    provider_edit_parser.set_defaults(handler=_provider_edit)

    provider_rotation_parser = provider_subparsers.add_parser("rotation", help="Enable or disable provider rotation")
    provider_rotation_parser.add_argument("provider_id")
    provider_rotation_group = provider_rotation_parser.add_mutually_exclusive_group(required=True)
    provider_rotation_group.add_argument("--enable", action="store_true", help="Enable provider rotation")
    provider_rotation_group.add_argument("--disable", action="store_true", help="Disable provider rotation")
    provider_rotation_parser.set_defaults(handler=_provider_rotation)

    provider_node_parser = provider_subparsers.add_parser("node", help="Change provider node settings")
    provider_node_parser.add_argument("provider_id")
    provider_node_parser.add_argument("node_id")
    provider_node_parser.add_argument("--rotation", action="store_true", required=True)
    provider_node_group = provider_node_parser.add_mutually_exclusive_group(required=True)
    provider_node_group.add_argument("--enable", action="store_true", help="Enable node rotation")
    provider_node_group.add_argument("--disable", action="store_true", help="Disable node rotation")
    provider_node_parser.set_defaults(handler=_provider_node)

    node_group_parser = subparsers.add_parser("node-group", help="Manage node groups")
    node_group_subparsers = node_group_parser.add_subparsers(dest="node_group_command")

    node_group_list_parser = node_group_subparsers.add_parser("list", help="List node groups")
    node_group_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    node_group_list_parser.set_defaults(handler=_node_group_list)

    node_group_create_parser = node_group_subparsers.add_parser("create", help="Create a node group")
    node_group_create_parser.add_argument("name")
    node_group_create_parser.set_defaults(handler=_node_group_create)

    node_group_add_profile_parser = node_group_subparsers.add_parser(
        "add-profile", help="Add a profile to a node group"
    )
    node_group_add_profile_parser.add_argument("group")
    node_group_add_profile_parser.add_argument("profile")
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
    node_group_select_parser.set_defaults(handler=_node_group_select)

    dns_parser = subparsers.add_parser("dns", help="Manage DNS v2 policy and state")
    dns_subparsers = dns_parser.add_subparsers(dest="dns_command")

    dns_status_parser = dns_subparsers.add_parser("status", help="Show DNS v2 status")
    _add_dns_common_paths(dns_status_parser)
    dns_status_parser.add_argument("--json", action="store_true", help="Print JSON")
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

    config_parser = subparsers.add_parser("config", help="Manage WatchdogVPN configuration")
    config_subparsers = config_parser.add_subparsers(dest="config_command")

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

    stats_status_parser = stats_subparsers.add_parser("status", help="Show metrics status")
    stats_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_status_parser.set_defaults(handler=_stats_status)

    stats_summary_parser = stats_subparsers.add_parser("summary", help="Show aggregate metrics summary")
    stats_summary_parser.add_argument("--json", action="store_true", help="Print JSON")
    stats_summary_parser.set_defaults(handler=_stats_summary)

    stats_purge_parser = stats_subparsers.add_parser("purge", help="Purge local observability metrics")
    stats_purge_parser.add_argument("--yes", action="store_true", help="Confirm metrics purge")
    stats_purge_parser.set_defaults(handler=_stats_purge)

    stats_privacy_parser = stats_subparsers.add_parser("privacy-mode", help="Set metrics privacy mode")
    stats_privacy_parser.add_argument(
        "mode",
        choices=[item.value for item in MetricsRedactionMode],
        help="Metrics privacy mode",
    )
    stats_privacy_parser.set_defaults(handler=_stats_privacy_mode)

    rules_parser = subparsers.add_parser("rules", help="Inspect configured routing rules")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command")

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

    app_policy_parser = subparsers.add_parser(
        "app-policy",
        help="Manage minimal Linux app/process policy",
    )
    app_policy_subparsers = app_policy_parser.add_subparsers(dest="app_policy_command")

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

    return parser


def _connection_connect(args: argparse.Namespace) -> int:
    response = WatchdogIPCClient().connect(args.profile_id)
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Connected",
    )


def _connection_disconnect(args: argparse.Namespace) -> int:
    response = WatchdogIPCClient().disconnect()
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Disconnected",
    )


def _connection_status(args: argparse.Namespace) -> int:
    response = WatchdogIPCClient().status()
    if args.json:
        _print_json(response.to_dict())
        return 0 if response.ok else 70
    if not response.ok:
        _error(response.error or "daemon command failed")
        return 70
    _print_connection_state(response.payload.get("state", {}))
    return 0


def _connection_rotate(args: argparse.Namespace) -> int:
    response = WatchdogIPCClient().rotate(force=bool(args.force))
    return _connection_response_output(
        response,
        json_output=bool(args.json),
        success_label="Rotation requested",
    )


def _uninstall(args: argparse.Namespace) -> int:
    mode = _uninstall_mode(args)
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
    }
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
    if value:
        candidates = [Path(value).expanduser()]
    elif os.environ.get("WATCHDOGVPN_UNINSTALL_SCRIPT"):
        candidates = [Path(os.environ["WATCHDOGVPN_UNINSTALL_SCRIPT"]).expanduser()]
    else:
        candidates = []
        if os.environ.get("WATCHDOGVPN_REPO_DIR"):
            candidates.append(Path(os.environ["WATCHDOGVPN_REPO_DIR"]).expanduser() / "uninstall.sh")
        candidates.append(Path.cwd() / "uninstall.sh")
        candidates.append(Path(__file__).resolve().parents[1] / "uninstall.sh")
    script = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
    if not script.exists():
        raise FileNotFoundError(
            f"uninstall.sh not found; run from the WatchdogVPN checkout or set WATCHDOGVPN_REPO_DIR"
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
    print("Command:")
    print("  " + " ".join(str(part) for part in data["command"]))


def _connection_response_output(response: Response, json_output: bool, success_label: str) -> int:
    if json_output:
        _print_json(response.to_dict())
        return 0 if response.ok else 70
    if not response.ok:
        _error(response.error or "daemon command failed")
        return 70
    print(success_label)
    if "profile_id" in response.payload:
        print(f"Profile: {response.payload['profile_id']}")
    if "state" in response.payload:
        _print_connection_state(response.payload["state"])
    return 0


def _print_connection_state(state: dict) -> None:
    print(f"Status: {state.get('status', 'unknown')}")
    print(f"Mode: {state.get('mode', '-')}")
    active_profile_id = state.get("active_profile_id") or "-"
    print(f"Active profile: {active_profile_id}")
    print(f"TUN: {_on_off(bool(state.get('tun_active', False)))}")
    print(f"Proxy: {_on_off(bool(state.get('proxy_active', False)))}")
    print(f"Kill switch: {_on_off(bool(state.get('kill_switch_active', False)))}")


def _profile_add(args: argparse.Namespace) -> int:
    provider = ManualProvider(rotation_prompt=_prompt_rotation_pool)
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
    print(f"Imported {len(imported)} profile(s).")
    for item in imported:
        print(f"{item.id}\t{item.protocol.value}\t{item.name}\trotation={_on_off(item.in_rotation_pool)}")
    return 0


def _profile_list(args: argparse.Namespace) -> int:
    store = ProfileStore()
    if args.pool:
        profiles = pool_builder.build_pool(store, ProviderStore(), AppConfig().load())
    else:
        profiles = store.list()
    if args.json:
        print(json.dumps([profile.to_dict() for profile in profiles], indent=2, sort_keys=True))
        return 0
    if not profiles:
        print("No profiles found.")
        return 0
    print("ID\tProtocol\tSource\tEnabled\tRotation\tHealth\tName")
    for profile in profiles:
        print(
            "\t".join(
                [
                    profile.id,
                    profile.protocol.value,
                    profile.source.value,
                    _on_off(profile.enabled),
                    _on_off(profile.in_rotation_pool),
                    profile.health_status,
                    profile.name,
                ]
            )
        )
    return 0


def _profile_remove(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    store.remove(profile.id)
    print(f"Removed profile: {profile.id}")
    return 0


def _profile_set_enabled(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.enabled = bool(args.enabled)
    store.update(profile)
    state = "enabled" if profile.enabled else "disabled"
    print(f"Profile {state}: {profile.id}")
    return 0


def _profile_rotation(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.in_rotation_pool = bool(args.enable)
    store.update(profile)
    state = "enabled" if profile.in_rotation_pool else "disabled"
    print(f"Profile rotation {state}: {profile.id}")
    return 0


def _provider_add(args: argparse.Namespace) -> int:
    url = args.url or _prompt_required("Provider URL")
    name = args.name if args.name is not None else _prompt_optional("Provider name")
    provider = SubscriptionProvider().add(url, name)
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
    print("ID\tName\tEnabled\tNodes\tLast update\tTraffic\tExpires")
    for summary in summaries:
        print(
            "\t".join(
                [
                    summary["id"],
                    summary["name"],
                    _on_off(bool(summary["rotation_enabled"])),
                    str(summary["node_count"]),
                    str(summary["last_updated"] or "-"),
                    str(summary["traffic"] or "-"),
                    str(summary["expires_at"] or "-"),
                ]
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
        for provider_id, result in results.items():
            print(f"{provider_id}\t{result}")
        return 0
    changes = provider.update(args.provider_id)
    print(f"Provider updated: {args.provider_id} changes={changes}")
    return 0


def _provider_remove(args: argparse.Namespace) -> int:
    _require_provider(ProviderStore(), args.provider_id)
    SubscriptionProvider().remove(args.provider_id)
    print(f"Removed provider: {args.provider_id}")
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
    print(f"Updated provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"URL: {_redact_url(provider.url)}")
    return 0


def _provider_rotation(args: argparse.Namespace) -> int:
    provider_store = ProviderStore()
    provider = _require_provider(provider_store, args.provider_id)
    provider.rotation_enabled = bool(args.enable)
    provider_store.update(provider)
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
        raise ParseError(f"node group already exists: {args.name}")
    group = NodeGroup(name=args.name)
    store.add(group)
    print(f"Created node group: {group.name}")
    return 0


def _node_group_add_profile(args: argparse.Namespace) -> int:
    profile = _require_profile(ProfileStore(), args.profile)
    group = NodeGroupStore().add_member_profile(args.group, profile.id)
    print(f"Added profile to node group: {group.name} profile={profile.id}")
    return 0


def _node_group_select(args: argparse.Namespace) -> int:
    store = NodeGroupStore()
    _require_node_group(store, args.group)
    if args.selection == "auto":
        group = store.set_selection(args.group, NodeGroupSelectionMode.AUTO)
        print(f"Node group selection set to auto: {group.name}")
        return 0
    profile = _require_profile(ProfileStore(), args.selection)
    group = store.set_selection(args.group, NodeGroupSelectionMode.MANUAL, profile.id)
    print(f"Node group selection pinned: {group.name} profile={profile.id}")
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
    if args.key not in CONFIG_SET_KEYS:
        supported = ", ".join(
            [
                "mode",
                "routing-policy",
                "capture-modes",
                "default-route-action",
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
    diagnostic = diagnose_route(
        traffic=traffic,
        rule_groups=RuleStore().list_groups(),
        routing_state=StateManager().load(),
        trust_registry=trust_registry,
        app_policy=AppPolicyStore().load_or_disabled().policy,
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
    if args.enabled:
        store.enable_group(args.group)
    else:
        store.disable_group(args.group)
    group = store.get_group(args.group)
    if group is None:
        raise RuleStoreError(f"rule group not found: {args.group}")
    data = {"group": group.to_dict()}
    if args.json:
        _print_json(data)
    else:
        print(f"Rule group {'enabled' if group.enabled else 'disabled'}: {group.name}")
    return 0


def _rules_add_rule(args: argparse.Namespace) -> int:
    try:
        rule = Rule(
            id=args.rule_id,
            action=args.action,
            conditions=_parse_rule_conditions(args.condition),
        )
    except ValueError as exc:
        raise ParseError(str(exc)) from exc
    group = RuleStore().add_rule(args.group, rule)
    data = {"added": rule.to_dict(), "group": group.to_dict()}
    if args.json:
        _print_json(data)
    else:
        print(f"Added rule: {group.name}/{rule.id}")
        print(f"Action: {rule.action}")
        print(f"Conditions: {_format_rule_conditions(rule.conditions)}")
    return 0


def _rules_remove_rule(args: argparse.Namespace) -> int:
    group = RuleStore().remove_rule(args.group, args.rule_id)
    data = {"removed": args.rule_id, "group": group.to_dict()}
    if args.json:
        _print_json(data)
    else:
        print(f"Removed rule: {group.name}/{args.rule_id}")
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
    if not args.dry_run:
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
        elif not args.dry_run:
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
    store.save(policy)
    data = _app_policy_status_data(policy)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy {'enabled' if policy.enabled else 'disabled'}.")
    return 0


def _app_policy_set_mode(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    policy.mode = AppPolicyMode(args.mode)
    policy = AppPolicy.from_dict(policy.to_dict())
    store.save(policy)
    data = _app_policy_status_data(policy)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy mode set to: {policy.mode.value}")
    return 0


def _app_policy_set_default_action(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    policy.default_action = AppPolicyAction(args.default_action)
    policy = AppPolicy.from_dict(policy.to_dict())
    store.save(policy)
    data = _app_policy_status_data(policy)
    if args.json:
        _print_json(data)
    else:
        print(f"App policy default action set to: {policy.default_action.value}")
    return 0


def _app_policy_add(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    match: dict[str, list[str]] = {}
    if args.process_name:
        match["process_name"] = [args.process_name]
    if args.process_path:
        match["process_path"] = [args.process_path]
    rule_id = args.id or _next_app_policy_rule_id(policy, match, args.action)
    if any(rule.id == rule_id for rule in policy.rules):
        raise ValueError(f"app policy rule already exists: {rule_id}")
    rule = AppPolicyRule(
        id=rule_id,
        action=args.action,
        match=match,
    )
    policy.rules.append(rule)
    policy = AppPolicy.from_dict(policy.to_dict())
    store.save(policy)
    data = {"added": rule.to_dict(), "policy": _app_policy_status_data(policy)}
    if args.json:
        _print_json(data)
    else:
        print(f"Added app policy rule: {rule.id}")
        print(f"Action: {_app_policy_action_value(rule.action)}")
        print(f"Confidence: {rule.match_confidence.value}")
    return 0


def _app_policy_remove(args: argparse.Namespace) -> int:
    store = AppPolicyStore()
    policy = store.load()
    original_count = len(policy.rules)
    policy.rules = [rule for rule in policy.rules if rule.id != args.rule_id]
    if len(policy.rules) == original_count:
        raise ValueError(f"app policy rule not found: {args.rule_id}")
    policy = AppPolicy.from_dict(policy.to_dict())
    store.save(policy)
    data = {"removed": args.rule_id, "policy": _app_policy_status_data(policy)}
    if args.json:
        _print_json(data)
    else:
        print(f"Removed app policy rule: {args.rule_id}")
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
    print(f"DNS mode: {policy.mode.value}")
    print(f"TUN hijack: {_on_off(policy.tun_hijack)}")
    print(f"Resolver manager: {data['resolver_manager']['manager']}")
    print(f"Nameservers: {', '.join(data['resolver_manager']['nameservers']) or '-'}")
    print(f"Channels: {data['channels']['configured']}/{data['channels']['total']}")
    print(f"Static IP: {_on_off(policy.static_ip_enabled)} ({len(policy.static_ips)} entries)")
    print(f"Rules: {_on_off(policy.rules_enabled)} ({len(policy.rules)} rules)")
    print(f"FakeIP: {policy.fakeip_inet4_range}, {policy.fakeip_inet6_range}")
    print(f"ECS direct: {_on_off(policy.ecs_direct_enabled)}")
    print(f"Snapshot: {data['snapshot']['path']} ({data['snapshot']['status']})")
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
    diagnostic = diagnose_route_dns(
        traffic=traffic,
        rule_groups=RuleStore().list_groups(),
        dns_policy=_load_dns_policy(args),
        app_policy=AppPolicyStore().load_or_disabled().policy,
        routing_state=StateManager().load(),
        trust_registry=trust_registry,
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
        "would_apply": policy.mode != DNSMode.OFF and policy.tun_hijack,
        "rollback_plan": "restore saved DNS state from snapshot",
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
    }
    return _dns_apply_output(args, data)


def _dns_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ParseError("dns reset requires --yes")
    snapshot_path = _dns_snapshot_path(args)
    snapshot = _load_dns_snapshot(snapshot_path)
    manager = SystemDNSStateManager(resolv_conf_path=Path(args.resolv_conf_path))
    manager.restore_state(snapshot)
    try:
        snapshot_path.unlink()
    except FileNotFoundError:
        pass
    data = {
        "status": "restored",
        "snapshot_path": str(snapshot_path),
        "resolver_manager": snapshot.inventory.manager.value,
    }
    if args.json:
        _print_json(data)
    else:
        print("DNS state restored.")
        print(f"Snapshot: {snapshot_path}")
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
        },
        "snapshot": {
            "path": str(snapshot_path),
            "status": "present" if snapshot_path.exists() else "missing",
        },
    }


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


def _load_dns_snapshot(path: Path) -> DNSStateSnapshot:
    snapshot = load_snapshot(path)
    if snapshot is None:
        raise FileNotFoundError(path)
    return snapshot


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
        raise ParseError(f"profile not found: {profile_id}")
    return profile


def _require_provider(store: ProviderStore, provider_id: str) -> Provider:
    provider = store.get(provider_id)
    if provider is None:
        raise ProviderNotFoundError(f"provider not found: {provider_id}")
    return provider


def _require_node_group(store: NodeGroupStore, name: str) -> NodeGroup:
    group = store.get(name)
    if group is None:
        raise ParseError(f"node group not found: {name}")
    return group


def _node_group_summary(group: NodeGroup) -> dict:
    return group.to_dict()


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
        "metadata": metadata,
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


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def _redact_url(url: str) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/<redacted>"


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _exit() -> NoReturn:
    raise SystemExit(main())


if __name__ == "__main__":
    _exit()
